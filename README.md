
# Correlation Power Analysis (CPA) Attack on PRESENT Cipher

This repository contains the implementation of a **Correlation Power Analysis (CPA)** attack on the **PRESENT lightweight block cipher** to recover both the **first-round key** and the **80-bit master key** from power consumption traces.

## Overview

The project demonstrates how side-channel information, specifically power consumption during cryptographic operations, can be exploited to recover secret keys. Using recorded power traces and corresponding plaintexts, the implementation performs CPA to identify the correct key bytes by maximizing the statistical correlation between hypothetical leakage values and measured power traces.

## Features

- Correlation Power Analysis (CPA) implementation
- Recovery of the first-round subkey
- Reconstruction of the PRESENT master key
- Support for multiple datasets
- Hamming Weight leakage model
- Hamming Distance leakage model
- Pearson Correlation-based key ranking
- Comparison with alternative statistical metrics:
  - Mutual Information
  - KL Divergence
  - Kolmogorov-Smirnov Test
- Guessing Entropy evaluation
- Correlation evolution plots with increasing number of traces
- Documentation of the attack methodology and experimental observations

## Dataset

Each dataset contains:

- **15,000 power traces**
- **Trace length:** 2,500 sample points
- Corresponding plaintexts and ciphertexts

```
Power Traces Shape : (15000, 2500)
Plaintexts Shape   : (15000, 8)
Ciphertexts Shape  : (15000, 8)
```

## Objectives

- Recover the first-round key using CPA.
- Derive the corresponding PRESENT master key.
- Compare Hamming Weight and Hamming Distance leakage models.
- Evaluate different statistical distinguishers.
- Analyze attack efficiency using Guessing Entropy and correlation plots.

## Technologies Used

- Python
- NumPy
- SciPy
- Matplotlib
- Pandas

## Concepts Covered

- Side-Channel Attacks
- Correlation Power Analysis (CPA)
- Leakage Modeling
- Hamming Weight
- Hamming Distance
- Pearson Correlation
- Mutual Information
- KL Divergence
- Kolmogorov-Smirnov Test
- Guessing Entropy
- PRESENT Lightweight Block Cipher
