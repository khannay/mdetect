# AUTOGENERATED! DO NOT EDIT! File to edit: ../nbs/00_core.ipynb.

# %% auto 0
__all__ = ['FLAG_NAMES', 'flow_duration', 'PacketFlows', 'collect_flow_stats', 'hash_datafiles', 'load_training_validation',
           'ModelCandidate', 'ModelMetrics', 'evaluate', 'test_eval']

# %% ../nbs/00_core.ipynb 4
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

import ipaddress
from collections import OrderedDict
from datetime import datetime

import netaddr
import numpy as np
import pandas as pd
from scapy.all import *

import joblib
from fastcore.basics import patch 
import hashlib

import mdetect

# %% ../nbs/00_core.ipynb 8
def _get_fid(pkt):
    """Extract fid (five-tuple) from a packet: only focus on IPv4
    Parameters
    ----------

    Returns
    -------
        fid: five-tuple (IP src, IP dst, src port, dst port, protocol)
    """

    if IP in pkt and TCP in pkt:
        fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 'TCP')
    elif IP in pkt and UDP in pkt:
        fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 'UDP')
    elif ICMP in pkt:
        fid = ('', '', pkt[ICMP].sport, pkt[ICMP].dport, "ICMP")
    else: 
        fid = ('', '', -1, -1, "UNK")

    return fid

def _get_frame_time(pkt):
    return float(pkt.time)

def flow_duration(pkts: List) -> float:
    pkt_times = [float(pkt.time) for pkt in pkts]
    flow_duration = max(pkt_times) - min(pkt_times)
    return flow_duration
    


# %% ../nbs/00_core.ipynb 10
class PacketFlows:
    
    def __init__(self, 
                 pcap_file: Path, 
                 interval: float = 0, 
                 q_interval: float = 0.90,
                 min_pkts: int = 2, 
                 tcp_timeout: int = 600, 
                 udp_timeout: int = 600, 
                 verbose: int = 0):
        """
        Parameters
        ----------
        pcap: Path or str
            a pcap needed to processed.

        min_pkts: int (default is 2)
            the minimum number of packets of each flow is to control which flow should be kept
            and which one should be discarded. The default value is 2, i.e., all the flows which have less than 2 packets
            are discarded. It must be >= 2.

        tcp_timeout: int (default is 600s)
            a timeout is to split flow

        ucp_timeout: int (default is 600s)
            a timeout is to split flow

        verbose: int (default is 1)
            a print level is to control what information should be printed according to the given value.
            The higher the value is, the more info is printed.

        """
        self.min_pkts = min_pkts
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.verbose = verbose
        self.pcap_file = str(pcap_file)
        self.name = pcap_file.name
        
        # Seperate into seperate flows, not segmented by time
        full_flow = self._pcap2flows()
        # Get the time interval used to seperate flows by time segment
        self.interval = self._fetch_interval(full_flow, interval, q_interval)
        # Seperate into flows segmented by time, using the interval as the time segment
        self.flows = self.flows2subflows(full_flow, self.interval)
        
    def _fetch_interval(self, 
                        fflow: OrderedDict,
                        interval: float, 
                        q_interval: float) -> float:
        if interval > 0:
            return interval
        else:
            if q_interval > 0:
                self.flow_durations = [flow_duration(pkts) for fid, pkts in fflow]
                self.interval = self.split_interval(self.flow_durations, q_interval=q_interval)
                return self.interval
            else:
                msg = f'q_interval must be in [0, 1]! Current q_interval is {q_interval}.'
                raise ValueError(msg)
            
    def split_interval(self, 
                       flow_durations: List[float], 
                       q_interval: float =0.9):
        interval = np.quantile(flow_durations, q=q_interval)
        return interval
        
    def __getitem__(self, index: int):
        return self.flows[index] 
    
    def __len__(self):
        return len(self.flows)   
    
    def __iter__(self):
        return iter(self.flows)

    def summary(self):
        print(f'pcap_file: {self.pcap_file}')
        print("Number of flows: ", len(self.flows))
        print("Number of packets in each flow: ", [len(v[1]) for v in self.flows])
        
    @property
    def src_ports(self) -> np.array:
        return np.array([flow[0][2] for flow in self.flows])
        
    @property
    def dst_ports(self) -> np.array:
        return np.array([flow[0][3] for flow in self.flows])
        
    @property
    def protocols(self) -> np.array:
        return np.array([str(flow[0][4]) for flow in self.flows])

    def _pcap2flows(self) -> OrderedDict:
    
        # store all extracted flows into a dictionary, whose key is flow id ('fid': five-tuple) and value is packtes
        # that belongs to the flow.
        flows = OrderedDict()
        try:
            # iteratively get each packet from the pcap
            for i, pkt in enumerate(PcapReader(self.pcap_file)):
                if (TCP in pkt) or (UDP in pkt):

                    # this function treats bidirection flows as two sessions (hereafter, we use sessions
                    # and flows interchangeably).
                    fid = _get_fid(pkt)

                    if fid not in flows.keys():
                        flows[fid] = [pkt]
                    else:
                        flows[fid].append(pkt)
                else:
                    continue

        except Exception as e:
            msg = f'Parse PCAP error: {e}!'
            raise RuntimeError(msg)

        # split flows by TIMEOUT and discard flows that have less than "min_pkts" packets.
        n_pkts = 0
        new_flows = []  # store the preprocessed flows
        for i, (fid, pkts) in enumerate(flows.items()):
            n_pkts += len(pkts)
            if len(pkts) < max(2, self.min_pkts):
                # discard flows that have less than "max(2, flow_pkts_thres)" packets
                continue
            pkts = sorted(pkts, key=_get_frame_time, reverse=False)

            # split flows by TIMEOUT
            subflows = []
            for j, pkt in enumerate(pkts):
                pkt_time = _get_frame_time(pkt)
                if j == 0:
                    subflow_tmp = [pkt]
                    split_flow = False  # if a flow is not split with interval, label it as False, otherwise, True
                    continue
                if ('TCP' in fid) or (TCP in pkt):
                    # handle TCP packets, TCP is 6
                    # a timeout (the idle time) is the duration between the previous pkt and the current one.
                    if pkt_time - _get_frame_time(subflow_tmp[-1]) > self.tcp_timeout:
                        # Note: here subflow_tmp will only have 1 packet
                        subflows.append((fid, subflow_tmp))
                        subflow_tmp = [pkt]  # create a new subflow and store the current packet as the first packet of it.
                        split_flow = True
                    else:
                        subflow_tmp.append(pkt)
                elif ('UDP' in fid) or UDP in pkt:
                    # handle UDP packets, UDP is 17
                    if pkt_time - _get_frame_time(subflow_tmp[-1]) > self.udp_timeout:
                        subflows.append((fid, subflow_tmp))
                        subflow_tmp = [pkt]
                        split_flow = True
                    else:
                        subflow_tmp.append(pkt)
                else:  # other protocols
                    pass

            # if the current flow is not split by TIMEOUT, then add it into subflows
            if not split_flow:
                subflows.append((fid, subflow_tmp))
            else:
                pass # discard the last subflow_tmp
            
            new_flows.extend(subflows)

        new_flows = [(fid, pkts) for (fid, pkts) in new_flows if len(pkts) >= self.min_pkts]
        return new_flows


    def flows2subflows(self, 
                       full_flow: OrderedDict, 
                       interval: float,
                       ) -> List:
        """Split flows to subflows by interval

        Returns
        -------
        subflows: list
            each of subflow has at least "flow_ptks_thres" packets
        """

        new_flows = []  # store all subflows
        for i, (fid, pkts) in enumerate(full_flow):
            if (self.verbose > 3) and (i % 1000) == 0:
                print(f'{i}th_flow: len(pkts): {len(pkts)}')

            # Is it necessary to sort packets by arrival_times ?
            pkts = sorted(pkts, key=_get_frame_time, reverse=False)

            subflows = []
            # split flows by interval
            for j, pkt in enumerate(pkts):
                pkt_time = _get_frame_time(pkt)
                if j == 0:
                    subflow_tmp_start_time = pkt_time
                    subflow_tmp = [(subflow_tmp_start_time, pkt)]
                    split_flow = False  # if a flow is not split with interval, label it as False, otherwise, True
                    continue

                if ('TCP' in fid) or (TCP in pkt):
                    # handle TCP packets, TCP is 6
                    # a timeout (the idle time) is the duration between the previous pkt and the current one.
                    if pkt_time - subflow_tmp[-1][0] > interval:
                        subflows.append((fid, subflow_tmp))
                        subflow_tmp_start_time += int((pkt_time - subflow_tmp_start_time) // interval) * interval
                        # create a new subflow and store "subflow_tmp_start_time" as the time. Here, it will has a tiny
                        # difference of packet time between "subflow_tmp_start_time" and the current packet time.
                        subflow_tmp = [(subflow_tmp_start_time, pkt)]
                        split_flow = True
                    else:
                        subflow_tmp.append((pkt_time, pkt))

                elif ('UDP' in fid) or UDP in pkt:
                    # handle UDP packets, UDP is 17
                    if pkt_time - subflow_tmp[-1][0] > interval:
                        subflows.append((fid, subflow_tmp))
                        subflow_tmp_start_time += int((pkt_time - subflow_tmp_start_time) // interval) * interval
                        subflow_tmp = [(subflow_tmp_start_time, pkt)]
                        split_flow = True
                    else:
                        subflow_tmp.append((pkt_time, pkt))
                else:  # it's not possible, because flows only include TCP and UDP flows
                    pass

            # if the current flow is not split by interval, then add it into subflows
            if not split_flow:
                subflows.append([fid, subflow_tmp])
            else:
                # discard the last subflow_tmp
                pass

            new_flows.extend(subflows)

        # sort all flows by packet arrival time, each flow must have at least two packets
        subflows = []
        for fid, subflow_tmp in new_flows:
            if len(subflow_tmp) < max(2, self.min_pkts):
                continue
            subflows.append((fid, [pkt for pkt_time, pkt in subflow_tmp]))

        new_flows = subflows
        if self.verbose > 1:
            print(f'After splitting flows, the number of subflows: {len(new_flows)} and each of them has at least '
                f'{self.min_pkts} packets.')

        return new_flows
    
    def apply(self, func) -> np.array:
        """Apply func to each flow in flows.

        Returns:
          np.array of the results of func applied to each flow in flows.
        """
        
        return np.array(map(func, self.flows))
    
    
    @staticmethod 
    def iter_pcap_dict(pcap_file: str) -> Iterator:
        """Stream extracted dict mappings from PCAP file.

        Requires:
          self.pcap_file: string filepath of PCAP file

        Returns:
          Iterator of dicts with one dict per packet in pcap file.

            The dicts have the following key/value pairs:

              "time"      : time the packet was receieved in seconds since epoch
              "datetime"  : time the packet was received as a datetime object
              "length"    : length of packet in bytes
              "mac_src"   : source MAC address
              "mac_dst"   : destination MAC address
              "ip_src"    : source IP address
              "ip_dst"    : destination IP address
              "protocol"  : 'TCP', 'UDP', 'ICMP', or None
              "port_src"  : source port
              "port_dst"  : destination port
              "is_dns"    : True if packet is DNS packet, else False
              "dns_query" : string DNS query
              "dns_resp"  : string DNS response

        """
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if Ether not in pkt:
                    continue

                pkt_dict = {
                    'time': pkt.time,
                    'datetime': datetime.fromtimestamp(int(pkt.time)),
                    'length': len(pkt),
                    'mac_dst': pkt[Ether].dst,
                    'mac_src': pkt[Ether].src,
                    'ip_dst': None,
                    'ip_src': None,
                    'protocol': None,
                    'port_dst': None,
                    'port_src': None,
                    'is_dns': False,
                    'dns_query': None,
                    'dns_resp': None,
                }

                if IP in pkt:
                    pkt_dict['ip_dst'] = pkt[IP].dst
                    pkt_dict['ip_src'] = pkt[IP].src

                if TCP in pkt:
                    pkt_dict['port_dst'] = pkt[TCP].dport
                    pkt_dict['port_src'] = pkt[TCP].sport
                    pkt_dict['protocol'] = 'TCP'
                elif UDP in pkt:
                    pkt_dict['port_dst'] = pkt[UDP].dport
                    pkt_dict['port_src'] = pkt[UDP].sport
                    pkt_dict['protocol'] = 'UDP'
                elif ICMP in pkt:
                    pkt_dict['protocol'] = 'ICMP'

                try:
                    if (dnsqr := pkt.getlayer(DNSQR)) is not None:
                        pkt_dict.update(
                            is_dns=True,
                            dns_query=(
                                dnsqr.qname.decode('utf-8')
                                if isinstance(dnsqr.qname, bytes)
                                else dnsqr.qname,
                            )
                        )

                    if (dnsrr := pkt.getlayer(DNSRR)) is not None:
                        pkt_dict.update(
                            is_dns=True,
                            dns_resp=(
                                dnsrr.rrname.decode('utf-8')
                                if isinstance(dnsrr.rrname, bytes)
                                else dnsrr.rrname,
                            )
                        )
                except UnicodeDecodeError:
                    print("Decode error with {pkt.summary()}")

                yield pkt_dict

    @staticmethod
    def pcap2pandas(pcap_file: str or Path) -> pd.DataFrame:
        """Parse PCAP file into pandas DataFrame.

        Requires:
            self.pcap_file: string filepath of PCAP file

        Returns:
          DataFrame with one packet per row.
            column names are the keys from pcap_to_dict plus
            'ip_dst_int', 'ip_src_int', 'mac_dst_int', 'mac_dst_int'

        """
        df = pd.DataFrame(PacketFlows.iter_pcap_dict(str(pcap_file)))

        df['datetime'] = pd.to_datetime(df['datetime'])

        df['ip_dst_int'] = df['ip_dst'].apply(
            lambda x: None if x is None else int(ipaddress.ip_address(x)))

        df['ip_src_int'] = df['ip_src'].apply(
            lambda x: None if x is None else int(ipaddress.ip_address(x)))

        df['mac_dst_int'] = df['mac_dst'].apply(
            lambda x: None if x is None else int(netaddr.EUI(x)))

        df['mac_src_int'] = df['mac_src'].apply(
            lambda x: None if x is None else int(netaddr.EUI(x)))

        df['time_normed'] = df['time'].apply(lambda x: x - df.iloc[0]['time'])

        df.sort_index(axis=1, inplace=True)
        
        return df


# %% ../nbs/00_core.ipynb 14
FLAG_NAMES = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']

def _parse_tcp_flgs(tcp_flgs: List[str]) -> np.ndarray:
    
    flgs = {
        'F': 0,
        'S': 1,
        'R': 2,
        'P': 3,
        'A': 4,
        'U': 5,
        'E': 6,
        'C': 7,
    }

    flg_counts = np.zeros(8)
    for flg in tcp_flgs:
        if flg in flgs.keys():
            flg_counts[flgs[flg]] += 1

    return flg_counts

@patch 
def header_features(self: PacketFlows) -> np.ndarray:

    features = []
    for fid, pkts in self.flows:
        flgs_lst = np.zeros(8)  # 8 TCP flags
        header_features = []
        for i, pkt in enumerate(pkts):
            if not hasattr(pkt.payload, 'proto'):
                continue
            if pkt.payload.proto == 6:  # tcp
                flgs_lst += _parse_tcp_flgs(pkt.payload.payload.flags) # parses tcp.flgs
            # TODO: figure out this ttl part
            #header_features.append(pkt.payload.ttl)
        features.append(flgs_lst)

    return np.array(features)



# %% ../nbs/00_core.ipynb 18
@patch 
def count_http_raw_occurances(self: PacketFlows, 
                              filter: bytes) -> np.ndarray:
    
    def http_filter(packet, filter):
       return (TCP in packet and Raw in packet and bytes(packet[Raw]).startswith(filter))
    
    found = np.zeros(len(self.flows))
    counter = 0 
    for fid, pkts in self.flows:
        for i, pkt in enumerate(pkts):
            if http_filter(pkt, filter = filter):
                found[counter] += 1
        counter += 1
    return found



# %% ../nbs/00_core.ipynb 22
@patch 
def IAT_features(self: PacketFlows) -> List[np.array]:
    """Extract interarrival times (IAT) features from flows.
    Parameters
    ----------

    Returns
    -------
    features: a numpy array
        iats
    """
    
    features = []
    for fid, pkts in self.flows:
        pkt_times = [_get_frame_time(pkt) for pkt in pkts]
        iats = np.diff(pkt_times)
        features.append(iats)
    return features

@patch
def size_features(self: PacketFlows) -> List[np.array]:
    """Extract packet sizes features from flows
    Parameters
    ----------

    Returns
    -------
    features: a list
        sizes
    """

    features = []
    for fid, pkts in self.flows:
        sizes = [len(pkt) for pkt in pkts]
        features.append(sizes)

    return np.array(features)


@patch
def stats_features(flows: PacketFlows) -> np.array:
    """get basic stats features, which includes duration, pkts_rate, bytes_rate, mean,
    median, std, q1, q2, q3, min, and max.

    Returns
    -------
    features: a list
        stats
    """

    features = []
    for _, pkts in flows:
        sizes = [len(pkt) for pkt in pkts]

        sub_duration = flow_duration(pkts)
        num_pkts = len(sizes)  # number of packets in the flow
        num_bytes = sum(sizes)  # all bytes in sub_duration  sum(len(pkt))
        if sub_duration == 0:
            pkts_rate = 0.0
            bytes_rate = 0.0
        else:
            pkts_rate = num_pkts / sub_duration  
            bytes_rate = num_bytes / sub_duration

        q1, q2, q3 = np.quantile(sizes, q=[0.25, 0.5, 0.75])  # q should be [0,1] and q2 is np.median(data)
        base_features = [sub_duration, pkts_rate, bytes_rate, np.mean(sizes), np.std(sizes),
                         q1, q2, q3, np.min(sizes), np.max(sizes), num_pkts, num_bytes]

        features.append(base_features)

    return np.array(features)

@patch 
def stats_features_names(self: PacketFlows) -> List[str]:
    return ['duration', 
            'pkts_rate', 
            'bytes_rate', 
            'mean_size', 
            'std_sizes', 
            'q1_sizes', 
            'q2_sizes', 
            'q3_sizes', 
            'min_sizes', 
            'max_sizes', 
            'num_pkts', 
            'num_bytes']


# %% ../nbs/00_core.ipynb 35
def collect_flow_stats(pcap_file: Path) -> pd.DataFrame:
    
    pf = PacketFlows(pcap_file, verbose=0)
    stats_features = pf.stats_features()
    
    tcp_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
    udp_ports = [67, 68, 123, 161, 500, 514]
    total_ports = tcp_ports + udp_ports 
    
    # Ports from the flow 
    src_ports = pd.Categorical(pf.src_ports, categories=total_ports)
    dst_ports = pd.Categorical(pf.dst_ports, categories=total_ports)
    protocol = pd.Categorical(pf.protocols, categories=['tcp', 'udp', 'icmp'])
    
    # Headers from the flow
    headers_features =  pf.header_features()
    
    X = np.hstack([stats_features,
                      headers_features,
                      ])
    
    # Put the categorical features at the end of the dataframe 
    features_names = pf.stats_features_names()
    features_names  +=  ['flags_' + str(i) for i in FLAG_NAMES] 
    df = pd.DataFrame(X, columns=features_names)
    df['src_port'] = src_ports
    df['dst_port'] = dst_ports
    df['protocol'] = protocol 
    df = pd.get_dummies(df, columns=['protocol', 'src_port', 'dst_port'], drop_first=True)
    return df
    
    



# %% ../nbs/00_core.ipynb 39
def hash_datafiles(filelist: List[Path]) -> str:
    return hashlib.md5(("--".join(map(lambda x: str(x.name), filelist))).encode()).hexdigest()


def load_training_validation(malware_path: Path, # Path to Malware samples
                             benign_path: Path, # Path to Benign samples
                             load: bool = True, # Load the data from disk if already built
                             save: bool = True, # Save the data to disk, can be used for quick loading later
                             store_path= None, # Path to store the data
                             *args , 
                             **kwargs
                             ) -> Tuple[pd.DataFrame, np.array]:
    
    benign_files = list(benign_path.glob('*.pcap*'))
    malware_files = list(malware_path.glob('*.pcap*'))
    
    benign_files.sort()
    malware_files.sort()
     
    benign_filehash = hash_datafiles(benign_files)
    malware_filehash = hash_datafiles(malware_files)
    
    savefile_name = f'transformed_data_{benign_filehash}_{malware_filehash}.parquet.gz'
    
    # Load the data if files with those hashes exist
    if store_path is None:
        store_path = malware_path.parent / "tmp" / f"{benign_filehash}_{malware_filehash}" 
    store_path.parent.mkdir(exist_ok=True) # Create tmp directory if it doesn't exist
    store_path.mkdir(exist_ok=True) # Create the data directory if it doesn't exist
    files_already_exist = (store_path / savefile_name).exists() # boolean to check if the file exists
    
    if load and files_already_exist:
        print(f"Data found on disk at {store_path / savefile_name}: Loading from there")
        df = pd.read_parquet(store_path / savefile_name)
        y = df.label.values 
        X = df.drop(columns=['label'])
        return X, y
        
    Xm = pd.concat([collect_flow_stats(f) for f in malware_files])
    Xb = pd.concat([collect_flow_stats(f) for f in benign_files])
    X = pd.concat([Xm, Xb])
    y = np.array([1] * Xm.shape[0] + [0] * Xb.shape[0])

    if save:
        print(f"Saving data to disk as {(store_path / savefile_name)}")
        # Add the labels to the dataframe and save as a parquet file
        df_save = X.copy()
        df_save['label'] = y
        df_save.to_parquet(store_path / savefile_name, index=False)
        
        
    return X, y


# %% ../nbs/00_core.ipynb 42
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC 
from sklearn.neighbors import KNeighborsClassifier 
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import GaussianNB
import xgboost as xgb

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score,  accuracy_score,roc_auc_score
from sklearn.model_selection import cross_val_score
from sklearn.compose import ColumnTransformer 

from sklearn.metrics import RocCurveDisplay, ConfusionMatrixDisplay
from sklearn.calibration import CalibrationDisplay
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt

from dataclasses import dataclass
import seaborn as sns

# %% ../nbs/00_core.ipynb 48
@dataclass
class ModelCandidate():
    """ 
    A dataclass to hold a model and its name useful for keeping track of models and plotting routines 
    """
    model: Any
    name: str

@dataclass
class ModelMetrics():
    """ 
        A dataclass to hold a fitted model and routines to compute and plot its metrics. 
    """
    modelcand: ModelCandidate
    accuracy_score: float
    cv_scores: np.ndarray
    auc_score: float
    f1_score: float
    confusion_matrix: np.ndarray
    
    def plot_confusion_matrix(self, 
                              ax: plt.Axes or None = None,
                              *args, 
                              **kwargs) -> None:
        if ax is None:
            ax = plt.gca()
        ConfusionMatrixDisplay(confusion_matrix=self.confusion_matrix, 
                               display_labels=['Benign', 'Malware']
                               ).plot(ax=ax, cmap = 'BuGn', *args, **kwargs)
        ax.set_title(f"Confusion Matrix: {self.modelcand.name}")
        
    def plot_roc_curve(self, 
                       X_test, 
                       y_test, 
                       ax: plt.Axes or None = None, 
                       *args, 
                       **kwargs) -> None:
        if ax is None:
            ax = plt.gca()
        RocCurveDisplay.from_estimator(self.modelcand.model, 
                                       X_test, 
                                       y_test, 
                                       ax= ax,
                                       name = self.modelcand.name,  
                                       *args, 
                                       **kwargs)
        ax.set_title(f"ROC Curves")
        
    def plot_calibration_curve(self, 
                       X_test, 
                       y_test, 
                       ax: plt.Axes or None = None, 
                       *args, 
                       **kwargs) -> None:
        if ax is None:
            ax = plt.gca()
        CalibrationDisplay.from_estimator(self.modelcand.model, 
                                          X_test, 
                                          y_test, 
                                          ax=ax, 
                                          name=self.modelcand.name,
                                          *args, 
                                          **kwargs)
        ax.set_title(f"Calibration Curves")
        
    def importances(self, top: int = 10):
        try: 
            feature_importances = self.modelcand.model['model'].feature_importances_
            indices = np.argsort(feature_importances)[::-1]
            feature_names = X_train.columns
            for f in range(min(top, X_train.shape[1])):
                print("%d. feature %s (%f)" % (f + 1, features_names[indices[f]], feature_importances[indices[f]]))
        except AttributeError:
            print("feature_importances_ not available for this model")
            


# %% ../nbs/00_core.ipynb 50
def evaluate(candidate: ModelCandidate, # Pipeline with a name attribute and a model attribute
             X_train: np.ndarray, # Training data input features
             y_train: np.ndarray, # Training data labels (1= malware, 0 = benign)
             X_test: np.ndarray, # Test data input features 
             y_test: np.ndarray # Test data labels (1= malware, 0 = benign)
             ) -> ModelMetrics:
    
    model = candidate.model
    
    # Fit the model
    model.fit(X_train, y_train)
    
    # Precompute some metrics 
    cv_scores = cross_val_score(model, X_train, y_train, cv=5)
    acc_score = model.score(X_train, y_train)
    auc_score = roc_auc_score(y_train, model.predict_proba(X_train)[:, 1])
    f1_value = f1_score(y_train, model.predict(X_train))
    confusion_matrix_val = confusion_matrix(y_test, model.predict(X_test), normalize='true')
    metrics = {'accuracy_score': acc_score, 
               'cv_scores': cv_scores, 
               'auc_score': auc_score, 
               'f1_score': f1_value, 
               'confusion_matrix': confusion_matrix_val}
    
    candidate.model = model
    return ModelMetrics(candidate, **metrics)



# %% ../nbs/00_core.ipynb 67
def test_eval(malware: bool = True) -> pd.DataFrame:
    TPATH = DATA_PATH / 'test/malware' if malware else DATA_PATH / 'test/benign'
    test_type = 'malware' if malware else 'benign'
    test_files = list(TPATH.glob('**/*.pcap'))
    Xt = pd.concat([collect_flow_stats(f) for f in test_files], axis=0)
    model_names = [] 
    accuracy_scores = [] 
    for m in fit_models:
        model = m.modelcand.model
        y_true = np.ones(Xt.shape[0]) if malware else np.zeros(Xt.shape[0])
        accuracy = 1.0 - np.abs(model.predict(Xt) - y_true).sum() / Xt.shape[0]
        print(f"Model {m.modelcand.name} has accuracy {accuracy:.2f} on {test_type} test data flows")
        model_names.append(m.modelcand.name)
        accuracy_scores.append(accuracy) 
    return pd.DataFrame({'model': model_names, 'accuracy': accuracy_scores, 'test_type': [test_type] * len(model_names) })
     
