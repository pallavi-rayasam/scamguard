# ScamGuard
### Agentic AI-Based Proactive Scam Detection and Prevention System

ScamGuard is an AI-powered mini-project designed to identify and assess potential digital scams before individuals suffer financial loss.

It investigates suspicious messages, URLs, conversations, screenshots, and pre-transaction descriptions using a combination of deterministic risk analysis, threat intelligence, machine learning, and AI-assisted explanations.

**The goal is not just to detect suspicious activity, but to explain why something may be a scam, identify warning signs, assess the associated risk, and help users make informed decisions.**

---

## 1. Problem Statement

Digital fraud has become increasingly sophisticated. Scammers exploit social engineering techniques such as impersonation, urgency, fear, fake rewards, fraudulent job offers, phishing links, and requests for sensitive financial information.

Traditional detection approaches often rely on isolated keywords or conventional classification models. However, real-world scams frequently involve multiple interconnected warning signs distributed across messages, links, conversations, and transaction instructions.

ScamGuard addresses this challenge through a multi-layered investigation system that evaluates suspicious content, identifies scam indicators, checks URL reputation, and presents understandable investigation findings.

## 2. Key Features

- **Suspicious Message Analysis:** Identifies potentially fraudulent language, suspicious requests, urgency, manipulation techniques, and scam-related patterns.
- **URL Threat Intelligence:** Evaluates submitted URLs using structural checks and external threat-intelligence services.
- **Contextual Risk Assessment:** Calculates an overall risk score using detected indicators and their combinations.
- **AI-Assisted Explanations:** Generates understandable explanations of investigation findings using a language model.
- **Experimental ML Classification:** Provides supplementary scam predictions using a TF-IDF and Logistic Regression model.
- **Screenshot OCR:** Extracts text from uploaded screenshots using image preprocessing and OCR.
- **Investigation Reports:** Generates structured reports containing risk assessments, detected indicators, URL verification results, and recommendations.
- **Admin Dashboard:** Provides analytics covering investigations, scam categories, risk distributions, provider failures, and system activity.
- **Secure Authentication:** Supports user authentication and role-based administrative access.

## 3. How It Works

ScamGuard follows a layered investigation workflow:

1. **Input Submission:** Users submit suspicious messages, URLs, conversations, screenshots, or pre-transaction descriptions.
2. **Content Processing:** The backend processes the submitted information and extracts relevant text and URLs.
3. **Indicator Detection:** The analysis engine identifies suspicious patterns and scam-related indicators.
4. **URL Verification:** Applicable URLs undergo structural checks and external threat-intelligence checks.
5. **Risk Assessment:** A deterministic scoring engine evaluates the findings and assigns a risk score and risk level.
6. **AI-Assisted Explanation:** The language model generates a human-readable explanation without overriding the deterministic assessment.
7. **Investigation Results:** Users receive findings, risk information, and recommended precautions.

## 4. Risk Assessment

ScamGuard uses a deterministic rule-based engine as its primary risk assessment mechanism.

| Risk Score | Risk Level |
|---|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

The engine evaluates detected indicators and their combinations to determine the overall risk.

The experimental ML model provides an additional advisory prediction. It does not override or modify the deterministic risk score.

## 5. Technology Stack

### Frontend
- React
- TypeScript
- Vite
- Tailwind CSS

### Backend
- Python
- FastAPI
- Pydantic
- SQLAlchemy
- Alembic

### Database
- PostgreSQL – Production database
- SQLite – Local development and testing

### Artificial Intelligence and Machine Learning
- Groq API – AI-assisted explanations
- Scikit-learn – Machine learning
- TF-IDF – Text feature extraction
- Logistic Regression – Experimental scam classification
- Deterministic Rule Engine – Primary risk assessment

### Threat Intelligence
- Google Safe Browsing API
- VirusTotal API

### Image Processing and OCR
- OpenCV
- Tesseract OCR

### Deployment and Infrastructure
- Docker
- Docker Compose
- Render – Backend and URL scanner hosting
- Vercel – Frontend hosting
- Neon – Managed PostgreSQL database

## 6. System Architecture

ScamGuard separates its frontend, backend investigation services, database, and external integrations.

- **Frontend:** Provides the interface for submitting suspicious content and viewing investigation results.
- **Backend API:** Handles authentication, input processing, investigation workflows, and report generation.
- **Rule-Based Analysis Engine:** Identifies scam indicators and calculates the primary risk score.
- **Machine Learning Component:** Provides supplementary text classification.
- **LLM Integration:** Generates explanations of investigation findings.
- **URL Scanner Service:** Performs URL checks and communicates with external threat-intelligence providers.
- **Database:** Stores user accounts, investigations, reports, and administrative analytics data.

## 7. Project Structure

```text
ScamGuard/
├── backend/
│   ├── app/
│   ├── migrations/
│   └── tests/
├── frontend/
│   └── src/
├── url_scanner/
├── ml/
├── data/
│   └── seed/
├── docs/
│   └── testing/
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## 8. Local Installation and Setup

### Prerequisites
- Python 3.12 or 3.13
- Node.js 24+
- npm 11+

Local development uses SQLite and does not require Docker or PostgreSQL.

### Step 1: Clone the Repository

```bash
git clone https://github.com/pallavi-rayasam/scamguard.git
cd scamguard
```

### Step 2: Configure Environment Variables

```powershell
Copy-Item .env.example .env
```

Generate an application secret:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Add the generated value to `APP_SECRET_KEY` in `.env`.

Configure the essential local settings:

```dotenv
APP_ENV=development
APP_SECRET_KEY=your-generated-secret
COOKIE_SECURE=false
DATABASE_URL=sqlite:///./local.db
FRONTEND_ORIGIN=http://localhost:5173
URL_SCANNER_URL=http://localhost:8001
```

Keep API keys and production credentials private. Never commit your actual `.env` file.

### Step 3: Install and Start the Backend

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e "backend[dev]"
Set-Location backend
alembic upgrade head
python -m app.db.seed
uvicorn app.main:app --reload
```

Backend: `http://localhost:8000`

API documentation: `http://localhost:8000/docs`

### Step 4: Install and Start the Frontend

Open another terminal:

```powershell
Set-Location frontend
npm ci
npm run dev
```

Frontend: `http://localhost:5173`

### Step 5: Start the URL Scanner

For local URL scanning outside Docker Compose, install its dependencies from the repository root:

```powershell
pip install -r url_scanner/requirements.txt
uvicorn url_scanner.main:app --host 127.0.0.1 --port 8001
```

## 9. Testing

Run backend tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests
```

Run frontend tests:

```powershell
Set-Location frontend
npm test
```

Refer to [the testing report](docs/testing/test-report.md) for verification results, coverage details, and known limitations.

## 10. Important Limitations

ScamGuard is an advisory system, not a financial institution or payment gateway.

- A low-risk result does not guarantee that content is legitimate.
- A clean URL reputation result does not guarantee website safety.
- Threat-intelligence results depend on external provider availability and coverage.
- AI-generated explanations may contain inaccuracies.
- The experimental ML model may produce false positives and false negatives.
- ScamGuard does not initiate, approve, block, or reverse financial transactions.
- The system does not independently verify a payment recipient's identity.

Users should verify suspicious requests through trusted official channels before transferring money or sharing sensitive information.

## 11. Project Status

ScamGuard is an implemented mini-project exploring deterministic risk assessment, machine learning, threat intelligence, and AI-assisted investigation workflows for digital fraud prevention.

For implementation progress and verified functionality, refer to [CHECKLIST.md](CHECKLIST.md).

---

### ScamGuard
**Detect Suspicious Activity. Understand the Risk. Stay Protected.**
