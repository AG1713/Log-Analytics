# AI Proactive SIEM

An AI-powered Security Information and Event Management (SIEM) system that uses machine learning to classify and visualize network intrusion data from the UNSW-NB15 dataset.

---

## Project Structure

```
ai-proactive-siem/
├── backend/
│   ├── trained_model/
│   │   ├── unsw_attack_classifier.pkl
│   │   └── unsw_label_encoder.pkl
│   ├── UNSW_NB15_testing-set.csv
│   ├── ml_service.py
│   ├── main.py
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── components/
    │   │   └── ui/              # shadcn/ui components
    │   ├── pages/
    │   │   ├── dashboard/
    │   │   ├── alerts/
    │   │   ├── chatbot/
    │   │   └── fim/
    │   ├── sidebar/
    │   │   └── AppSideBar.jsx
    │   ├── App2.jsx             # Layout with sidebar
    │   ├── main.jsx             # Router config
    │   └── index.css            # Global theme
    └── package.json
```

---

## Prerequisites

- Python 3.8+
- Node.js 18+
- npm

---

## Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload
```

Backend runs on `http://localhost:8000`.

API Endpoints:
- `GET /attack_summary` — returns model predictions and attack statistics

---

## Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start the dev server
npm run dev
```

Frontend runs on `http://localhost:5173`.

---

## Tech Stack

### Backend
- **FastAPI** — REST API
- **scikit-learn** — ML model (attack classifier)
- **pandas** — data processing
- **joblib** — model serialization

### Frontend
- **React 19** + **Vite**
- **Tailwind CSS v4**
- **shadcn/ui** — component library (sidebar, cards)
- **Recharts** — data visualization
- **React Router v7** — routing

### Dataset
- **UNSW-NB15** — network intrusion detection dataset with 9 attack categories:
  `Normal`, `Fuzzers`, `Backdoors`, `DoS`, `Exploits`, `Generic`, `Reconnaissance`, `Shellcode`, `Worms`

---

## Notes

- The trained model files (`.pkl`) are required in `backend/trained_model/` to run the backend.
- The testing dataset CSV must be present at `backend/UNSW_NB15_testing-set.csv`.
- Make sure the backend is running before starting the frontend — the dashboard fetches data on load.
