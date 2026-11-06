# VTU mini-project outline

## Abstract

This project proposes an investigation platform for suspicious digital communications affecting Indian users. It combines deterministic message and URL indicators, extensible scam patterns, source-tagged evidence, and a transparent weighted risk score. The system provides advisory recommendations before a user responds or pays. It does not initiate payments or claim to verify a recipient's identity. Threat-intelligence and language-model results are reported only when real providers are configured and available.

## Problem statement

Users receive scam messages through SMS, chat, email, links, and payment requests. Existing checks are often fragmented and may not explain why an item is risky or whether an external source was actually queried. The system should collect relevant indicators, record their provenance and availability, and present calm, actionable advice without giving false assurances.

## Objectives

1. Accept text, URLs, conversations, and pre-transaction descriptions.
2. Normalize and redact sensitive values before storage or model use.
3. Route investigation stages deterministically and audit each stage.
4. Score risk using explainable, configurable weighted indicators.
5. Report evidence provenance, confidence limits, and unavailable providers.
6. Preserve feedback separately from curated evaluation labels.

## Methodology and evaluation plan

Seed an extensible, language-tagged scam-pattern catalogue. Build a hand-labelled Indian-scam set with documented source, licence, preprocessing, split, and annotator procedure. Compare a TF-IDF linear baseline, LLM-only explanations/classification, and the multi-stage pipeline on a held-out set using precision, recall, F1, confusion matrix, false-positive rate, and false-negative rate. No performance or novelty claim is made until the held-out evaluation is run.

## Expected outcomes, limitations, and future scope

Expected outcomes are explainable investigation reports and an auditable workflow. Initial language is English. Unknown URLs cannot be deemed safe. Threat-intel and OpenAI coverage depends on configured credentials, network availability, and rate limits. Hindi/Kannada, OCR, PDF export, deeper email-header checks, and notifications remain future scope unless implemented and verified.
