#!/bin/bash 

quarto render report.qmd --to md --output report.md
cp report.md ../report.md 

