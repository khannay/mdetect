#!/bin/bash 

quarto preview report.qmd --to md  --no-watch-inputs
cp report.md ../report.md 

