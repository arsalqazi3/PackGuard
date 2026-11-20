# PackGuard - AI Risk Prediction Layer
## Mukammal Technical Guide & Explanation (Roman Urdu)
**Author:** Ammar Hussain (AI/ML Lead)  
**Project:** PackGuard - AI-Assisted Multi-Layer Software Supply-Chain Defense Platform  
**University:** FAST-NUCES, Karachi Campus  

---

### 1. Asal Masla Kya Hai? (Problem Statement)

Jab developers AI coding assistants (jaise ChatGPT, Copilot, Cursor wagera) use karte hain, toh models aksar aise Python packages suggest kar dete hain jo dunya mein exist hi nahi karte. Isko academic research mein kehte hain **Package Hallucination**.

Attackers in hallucinated names par musalsal nazar rakhte hain. Jaise hi koi AI model naya hallucinated naam generate karta hai (maslan `flask-jwt-helper` ya `langchain-agent-tools`), attacker foran PyPI par jaa kar us naam se apna package register karta hai aur uske andar malware daal deta hai. Is hamle ko **Slopsquatting** kehte hain.

#### Aham Sawal: Kya Sirf 'PyPI Check' Kaafi Tha?
**Bilkul nahi!** Kyun ke attacker ne wo package already PyPI par register kar diya hota hai. Agar hum sirf API se check karein ke *"kya ye package exist karta hai?"*, toh PyPI kahega: **"Haan, HTTP 200 OK mojood hai"**, aur developer malware install kar lega. 

Isi liye hume **Machine Learning (XGBoost)** aur **Multi-Signal Feature Analysis** ki zaroorat hai jo package ke andar ke patterns ko pehchaane, chahe wo PyPI par mojood ho ya na ho.

---

### 2. PackGuard Ka Architecture Aur Ammar Ka Role

PackGuard aik 5-Layer Platform hai:
1. **Layer 1: Core Guard (Arslan & Asad)** - Pip installation proxy gateway jo basic existence aur typosquats check karta hai.
2. **Layer 2: AI Risk Prediction (Ammar / Aapka Kaam)** - Trained XGBoost Machine Learning model jo 16 signals aur SHAP Explainability ke zariye package ka risk score (0.00 se 1.00) nikalta hai.
3. **Layer 3: Runtime Guard (FYP-II)** - Sandboxed dynamic analysis jo suspicious packages ko isolated environment mein chala kar network/process monitor karta hai.
4. **Layer 4: Provenance & Audit** - Tamam decisions aur dependency records ko track karna.
5. **Layer 5: Unified Decision Engine** - Final action lena: `Allow`, `Warn`, ya `Block`.

---

### 3. Files Aur Components Ka Asal Kaam (Code Breakdown)

Hamare banaye gaye modules ka structure aur unka maqsad:

#### 1. `packguard/risk/config.py` (Central Settings)
Is file mein project ke tamam paths, decision thresholds (`Allow < 0.35`, `Block >= 0.70`), 5,000 popular packages ki list, aur AI ke common naming affixes (`helper`, `utils`, `client`, `wrapper`, `api`, `core`) define hain.

#### 2. `packguard/risk/dataset/pypi_cache.py` (High-Speed Metadata Cache)
PyPI ki official live API bar bar call karne se program bohot slow ho jata hai aur PyPI IP ban kar sakti hai. 
- Is file mein humne **SQLite database** banaya hai jo metadata ko save kar leta hai (lookup time **0.1ms**).
- Iske sath humne **500,566 PyPI packages ka offline master index** load kiya hai, jisse offline evaluation bina internet ke seconds mein complete ho jati hai.

#### 3. `packguard/risk/features/lexical.py` (Naam Ke Signals)
Ye file package ke naam ka tajziya karti hai:
- **Name Length & Shannon Entropy:** Naam kitna lamba hai aur characters kitne random hain.
- **AI Affix Match:** Kya naam mein `-helper`, `-utils`, `-tools`, `-wrapper` laga hai?
- **RapidFuzz Typosquat Distance:** Kya ye popular package (jaise `requests`) ka badla hua roop (`reqeusts`) toh nahi? Humne candidate-pruning lagayi hai taake 14 million string comparisons sirf 2 seconds mein ho jayein.

#### 4. `packguard/risk/features/metadata.py` (Registry Signals)
Package ki umar (Age in days), kitne releases hue hain, kya GitHub repository link mojood hai, aur maintainer info ko extract karta hai.

#### 5. `packguard/risk/features/pipeline.py` (Feature Pipeline)
Tamam 16 signals ko aik saath jor kar Pandas DataFrame aur NumPy vector banata hai jo model ko input diya jata hai.

#### 6. `packguard/risk/dataset/builder.py` (Ground Truth Curator)
Real PyPI packages (Safe class, $y=0$) aur Hallucinated/Typosquatted packages (Risk class, $y=1$) ka balanced dataset banata hai aur usko 3 hisson mein taqseem karta hai:
- **Train Set (70%):** 2,826 packages
- **Validation Set (15%):** 605 packages
- **Held-Out Test Set (15%):** 607 packages  
*(Zero Data Leakage: Test set ke packages train set mein bilkul nahi hain).*

#### 7. `packguard/risk/models/baseline.py` (Rule-Based Baseline)
Ye aik heuristic if-else engine hai jo comparison ke liye banaya gaya hai taake jury ko dikha sakein ke sirf simple rules kafi nahi hotay.

#### 8. `packguard/risk/models/xgboost_model.py` (Calibrated XGBoost Classifier)
Ye hamara asal Machine Learning model hai jo Decision Trees ke zariye complex patterns seekhta hai aur probability score nikalta hai.

#### 9. `packguard/risk/explainability/explainer.py` (TreeSHAP XAI)
Jury black-box models ko pasand nahi karti. SHAP mathematically batata hai ke model ne kisi package ko block kyun kiya:
- Maslan: *"Package is not on PyPI (+2.48)"*, *"Contains common AI suffix (+1.34)"*.

#### 10. `packguard/risk/train.py` (Training & Benchmark Script)
Pura pipeline train karta hai aur final evaluation metrics table print karta hai.

#### 11. `packguard/risk/service.py` (FastAPI /score API & score_package)
Microservice jo Arslan ke gateway ke sath direct integrate hoti hai (`POST /score`).

#### 12. `cli_demo.py` (Interactive Testing Tool)
Terminal par kisi bhi package ko live test karne ke liye tool.

---

### 4. Official Evaluation Numbers (Jury Ko Dikhane Ke Liye)

Held-Out Test Set ($N = 607$ packages) par hamare results ye hain:

| Model | Accuracy | Precision | Recall | F1-Score | False Positive Rate (FPR) | ROC-AUC | Missed Attacks (FN) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rule-Based Baseline** | 85.34% | 99.10% | 71.75% | 0.8324 | 0.0067 | 0.9695 | **87** |
| **PackGuard XGBoost** | **94.73%** | **95.10%** | **94.48%** | **0.9479** | 0.0502 | **0.9891** | **17** |

#### Asal Kamiyabi Kya Hai? (The Key Takeaway)
Rule-based baseline mein **87 attacks miss ho rahe thay (False Negatives)** kyun ke unke rules rigid thay. XGBoost model lagane se Missed Attacks 87 se gir kar sirf **17 reh gaye** (80.5% reduction in missed threats), aur Recall 71.75% se barh kar **94.48%** ho gayi!

---

### 5. Aap Khud Kaise Test Kar Sakte Hain?

Terminal kholiye aur run kijiye:
```powershell
python cli_demo.py
```
Koi bhi package name type karein (e.g. `requests`, `pandsa`, `flask-jwt-helper`, `torch`). Model foran aapko risk score, decision badge, aur SHAP reasons dikhayega!

---

### 6. Jury Questions Aur Unke Zabardast Jawabat

#### Q1: "Aap ne Machine Learning kyun lagayi, simple script se PyPI check kyun nahi kiya?"
> **Jawab:** *"Sir, PyPI check sirf tab kaam karta hai jab package upload na hua ho. Lekin Slopsquatting attack mein attacker hallucinated naam ko PyPI par pehle se register kar chuka hota hai, is liye API 200 OK deti hai. Hamara model naam ke lexical patterns, typosquat distance, metadata maturity, aur cross-model frequency ko judge kar ke pehchanta hai ke ye AI hallucination hai ya genuine package."*

#### Q2: "Data leakage se aap ne kaise bachaya?"
> **Jawab:** *"Sir, humne strict 3-way split enforce kiya hai (Train 70%, Validation 15%, aur Held-out Test 15%). Test set ke packages ko model training aur feature selection se bilkul alag rakha gaya hai taake evaluation 100% unbiased ho."*

#### Q3: "Agar kal hi kisi ne bilkul naya genuine package PyPI pe daala ho toh kya model usko block kar dega?"
> **Jawab:** *"Sir, naye genuine package ko protect karne ke liye hamara model multi-signal verification karta hai. Agar package ka naam clean hai, typosquat distance normal hai, aur documentation mojood hai toh model usko 'Allow' ya 'Warn' mein rakhta hai, bina waja block nahi karta."*
