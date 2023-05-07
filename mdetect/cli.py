# AUTOGENERATED! DO NOT EDIT! File to edit: ../nbs/02_cli.ipynb.

# %% auto 0
__all__ = ['main_train', 'main_transform', 'main_predict']

# %% ../nbs/02_cli.ipynb 2
import argparse
from .core import *
from pathlib import Path
import glob
import numpy as np


from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score,  accuracy_score,roc_auc_score
from sklearn.model_selection import cross_val_score

from sklearn.metrics import RocCurveDisplay, ConfusionMatrixDisplay
from sklearn.calibration import CalibrationDisplay
from sklearn.manifold import TSNE
from sklearn.compose import ColumnTransformer

import xgboost as xgb

import pandas as pd
import joblib

# %% ../nbs/02_cli.ipynb 3
def main_train():
    
    parser = argparse.ArgumentParser(description='Train a XGBoost model on PCAPs')
    parser.add_argument('--malware', type=str, default='data', help='Path to directory containing malware PCAPs')
    parser.add_argument('--benign', type=str, default='data', help='Path to directory containing benign PCAPs')
    parser.add_argument('--save', type=str, default='inference.pkl', help='Path to save the model')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    parser.add_argument('--test_size', type=float, default=0.3, help='Test split size')
    args = parser.parse_args()
    
    benign = Path(args.benign)
    malware = Path(args.malware)
    
    benign_files = list(benign.glob('*.pcap*'))
    malware_files = list(malware.glob('*.pcap*'))
    
    print(f"Found {len(benign_files)} benign files and {len(malware_files)} malware files")
    
    print("Processing PCAP files...")
    Xm = pd.concat([collect_flow_stats(f) for f in malware_files])
    Xb = pd.concat([collect_flow_stats(f) for f in benign_files])
    X = pd.concat([Xm, Xb])
    y = np.array([1] * Xm.shape[0] + [0] * Xb.shape[0])
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = args.test_size, random_state=args.seed)
    
    # Show the sizes of the training and test sets
    print("Training set has {} samples.".format(X_train.shape[0]))
    print("Test set has {} samples.".format(X_test.shape[0]))

    # Show the balance of labels in the training and test sets
    print("Training set has {} malware samples.".format(sum(y_train)))
    print("Training set has {} legitimate samples.".format(len(y_train) - sum(y_train)))
    
    baseline_pipe = [('scale', ColumnTransformer([('scaler', StandardScaler(), slice(0, 20))], remainder='passthrough'))]
    xgb_pipe = Pipeline(baseline_pipe + [('model', xgb.XGBClassifier(random_state=args.seed, eval_metric='logloss'))])
    modelcand = ModelCandidate(xgb_pipe, 'RandomForest')
    fit_model = evaluate(modelcand, X_train, y_train, X_test, y_test)
    
    # print all the model metrics
    print(f"Accuracy: {fit_model.accuracy_score}")
    print(f"Confusion Matrix: {fit_model.confusion_matrix}")
    print(f"F1 Score: {fit_model.f1_score}")
    print(f"AUC: {fit_model.auc_score}")
    print(f"Cross validation score: {fit_model.cv_scores}")
    
    # Save the model 
    pipeline_filename = args.save
    joblib.dump(fit_model.modelcand.model, pipeline_filename)
    
    print(f"Model saved to {pipeline_filename}")


# %% ../nbs/02_cli.ipynb 4
def main_transform():
    
    parser = argparse.ArgumentParser(description='Transform pcap files to features')
    parser.add_argument('--malware', type=str, default='data', help='path to malware pcap files')
    parser.add_argument('--benign', type=str, default='data', help='path to benign pcap files')
    parser.add_argument('--save', type=str, default=".", help='save the features to disk at this path')
    args = parser.parse_args()
    
    X, y = load_training_validation(Path(args.malware), Path(args.benign), save=True, load=False, save_path=Path(args.save))
    
    print(f"Features saved to {args.save}")

# %% ../nbs/02_cli.ipynb 5
def main_predict():
    
    parser = argparse.ArgumentParser(description='Predict if a pcap file is malware or benign, reports the number of malware flows detected')
    parser.add_argument('--data', type=str, default='data', help='path to pcap file')
    parser.add_argument('--model', type=str, help='path to model in pickle format, e.g. inference.pkl from the malware-train script')
    args = parser.parse_args()
    
    pipeline = joblib.load(args.model) # pretrained model
    Xt = pd.concat([collect_flow_stats(f) for f in [Path(args.data)]], axis=0)
    y_pred = pipeline.predict(Xt)
    
    print(f"Prediction: {y_pred.sum()} malware flows detected out of {len(y_pred)} flows")
    
    
    
    
    
    
