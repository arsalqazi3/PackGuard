import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from pathlib import Path

def create_guide_docx():
    doc = docx.Document()

    # Page Margins
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Styles
    title_p = doc.add_paragraph()
    title_run = title_p.add_run("PackGuard - AI Risk Prediction Layer")
    title_run.font.size = Pt(24)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(24, 76, 120)
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    sub_p = doc.add_paragraph()
    sub_run = sub_p.add_run("Complete Technical Guide & Explanation in Roman Urdu (Ammar - AI/ML Lead)")
    sub_run.font.size = Pt(13)
    sub_run.font.italic = True
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph("―" * 50).alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Section 1
    h1 = doc.add_heading("1. Asal Masla Kya Hai? (Problem Statement)", level=1)
    
    p = doc.add_paragraph()
    p.add_run("Jab developers AI coding assistants (ChatGPT, Copilot, Cursor) use karte hain, toh models aksar aise Python packages suggest kar dete hain jo dunya mein exist hi nahi karte. Isko kehte hain ")
    r = p.add_run("Package Hallucination")
    r.bold = True
    p.add_run(".\n\n")
    p.add_run("Attackers in hallucinated names par nazar rakhte hain. Jaise hi koi AI model naya hallucinated naam generate karta hai (maslan ")
    p.add_run("flask-jwt-helper").italic = True
    p.add_run("), attacker foran PyPI par jaa kar us naam se apna package register karta hai aur uske andar malware daal deta hai. Is hamle ko ")
    p.add_run("Slopsquatting").bold = True
    p.add_run(" kehte hain.")

    p2 = doc.add_paragraph()
    p2.add_run("Aham Sawal: Kya Sirf 'PyPI Check' Kaafi Tha?\n").bold = True
    p2.add_run("Bilkul nahi! Kyun ke attacker ne wo package already PyPI par register kar diya hota hai. Agar hum sirf API se check karein ke 'kya ye package exist karta hai?', toh PyPI kahega: ")
    p2.add_run("'Haan, 200 OK mojood hai'").bold = True
    p2.add_run(" aur developer malware install kar lega. Is liye hume Machine Learning aur Feature Signals ki zaroorat hai jo package ke andar ke patterns ko pehchaane.")

    # Section 2
    doc.add_heading("2. PackGuard Ka Architecture Aur Ammar Ka Kaam", level=1)
    p3 = doc.add_paragraph()
    p3.add_run("PackGuard aik 5-Layer Platform hai:\n")
    p3.add_run("• Layer 1 (Core Guard - Arslan & Asad): ")
    p3.add_run("Pip proxy gateway jo request intercept karta hai aur basic existence check karta hai.\n")
    p3.add_run("• Layer 2 (AI Risk Prediction - Ammar / Aapka Kaam): ")
    p3.add_run("XGBoost Machine Learning model jo 16 signals aur SHAP Explainability ke zariye risk score (0.0 se 1.0) nikalta hai.\n")
    p3.add_run("• Layer 3 (Runtime Guard - FYP-II): ")
    p3.add_run("Sandbox ke andar suspicious packages ko chala kar network/process monitor karna.\n")
    p3.add_run("• Layer 4 (Provenance & Audit): ")
    p3.add_run("Har dependency aur decision ka record rakhna.\n")
    p3.add_run("• Layer 5 (Unified Decision): ")
    p3.add_run("Final Faisla: Allow, Warn, ya Block.")

    # Section 3
    doc.add_heading("3. Har File Aur Component Ka Asal Kaam (Code Breakdown)", level=1)
    
    components = [
        ("config.py", "Central Settings", "Is file mein project ke tamam paths, thresholds (Allow < 0.35, Block >= 0.70), 5000 popular packages ki list, aur AI ke common affixes (helper, utils, client, api) define hain."),
        ("pypi_cache.py", "High-Speed Metadata Cache", "PyPI ki official API bar bar call karne se slow ho jati hai aur IP ban ho sakta hai. Is file mein humne SQLite database banaya hai jo metadata ko save kar leta hai (0.1ms lookup), aur 500,000 PyPI packages ka offline master index load karta hai."),
        ("lexical.py", "Naam Ke Signals (Lexical Features)", "Ye file package ke naam ka tajziya karti hai:\n- Name Length & Shannon Entropy (randomness measure)\n- AI Affix match (kya naam mein -helper ya -utils laga hai?)\n- RapidFuzz Typosquat Distance (kya ye 'requests' ka duplicate 'reqeusts' toh nahi?)"),
        ("metadata.py", "Registry Signals", "Package ki umar (Age in days), kitne releases hue hain, kya GitHub repository link mojood hai, aur author info ko extract karta hai."),
        ("pipeline.py", "Feature Pipeline", "Tamam 16 signals ko aik saath jor kar Pandas DataFrame aur NumPy vector banata hai jo model ko input diya jata hai."),
        ("builder.py", "Ground Truth Dataset Curator", "Real PyPI packages (Safe class, y=0) aur Hallucinated/Typosquatted packages (Risk class, y=1) ka balanced dataset banata hai aur usko 3 hisson mein taqseem karta hai: Train (70%), Val (15%), aur strictly Held-Out Test (15%) with ZERO data leakage."),
        ("baseline.py", "Rule-Based Baseline (Benchmark)", "Ye aik heuristic if-else engine hai jo comparison ke liye banaya gaya hai taake jury ko dikha sakein ke sirf if-else rules kafi nahi hotay."),
        ("xgboost_model.py", "Calibrated XGBoost Classifier", "Ye hamara asal AI model hai. Decision Trees ke zariye complex patterns seekhta hai aur probability score nikalta hai."),
        ("explainer.py", "TreeSHAP Explainability (XAI)", "Jury black-box models ko pasand nahi karti. SHAP mathematically batata hai ke model ne kisi package ko block kyun kiya (e.g. 'Not on PyPI (+2.48)', 'AI affix matched (+1.34)')."),
        ("train.py", "Training & Benchmark Script", "Pura pipeline train karta hai aur final evaluation metrics table print karta hai."),
        ("service.py", "FastAPI /score API & score_package()", "Microservice jo Arslan ke gateway ke sath direct integrate hoti hai (POST /score)."),
        ("cli_demo.py", "Interactive Testing Tool", "Terminal par kisi bhi package ko live test karne ke liye tool.")
    ]

    for filename, title, desc in components:
        p_comp = doc.add_paragraph()
        p_comp.add_run(f"• {filename} ({title}):\n").bold = True
        p_comp.add_run(desc)

    # Section 4
    doc.add_heading("4. Evaluation Numbers (Jury Ko Dikhane Ke Liye)", level=1)
    p_eval = doc.add_paragraph()
    p_eval.add_run("Held-Out Test Set (607 packages) par hamare results ye hain:\n")

    # Table
    table = doc.add_table(rows=3, cols=6)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Model", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]
    for col_idx, h in enumerate(headers):
        cell = table.cell(0, col_idx)
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True

    row1 = ["Rule-Based Baseline", "85.34%", "99.10%", "71.75%", "0.8324", "0.9695"]
    for col_idx, val in enumerate(row1):
        table.cell(1, col_idx).text = val

    row2 = ["PackGuard XGBoost", "94.73%", "95.10%", "94.48%", "0.9479", "0.9891"]
    for col_idx, val in enumerate(row2):
        cell = table.cell(2, col_idx)
        cell.text = val
        if cell.paragraphs[0].runs:
            cell.paragraphs[0].runs[0].bold = True

    p_conc = doc.add_paragraph()
    p_conc.add_run("\nAsal Kamiyabi Kya Hai? (The Key Takeaway)\n").bold = True
    p_conc.add_run("Rule-based baseline mein ")
    p_conc.add_run("87 attacks miss ho rahe thay (False Negatives)").bold = True
    p_conc.add_run(" kyun ke unke rules rigid thay. XGBoost model lagane se Missed Attacks 87 se gir kar sirf ")
    p_conc.add_run("17 reh gaye").bold = True
    p_conc.add_run(", aur Recall 71.75% se barh kar ")
    p_conc.add_run("94.48%").bold = True
    p_conc.add_run(" ho gayi!")

    # Section 5
    doc.add_heading("5. Jury Questions & Strong Answers (Tayyari)", level=1)
    
    qa = [
        ("Q1: Aap ne ML kyun use ki, simple script se PyPI check kyun nahi kiya?",
         "Answer: Sir, PyPI check sirf tab kaam karta hai jab package upload na hua ho. Lekin Slopsquatting attack mein attacker hallucinated naam ko PyPI par register kar chuka hota hai, is liye API 200 OK deti hai. Hamara model naam ke lexical patterns, typosquat distance, metadata maturity, aur cross-model frequency ko judge kar ke pehchanta hai ke ye AI hallucination hai ya genuine package."),
        
        ("Q2: Data leakage se aap ne kaise bachaya?",
         "Answer: Sir, humne 3-way split enforce kiya hai (Train 70%, Validation 15%, aur Held-out Test 15%). Test set ke packages ko model training aur feature selection se bilkul alag rakha gaya hai taake evaluation 100% unbiased ho."),
         
        ("Q3: Agar kal hi kisi ne bilkul naya genuine package PyPI pe daala ho toh kya model usko block kar dega?",
         "Answer: Sir, naye genuine package ko protect karne ke liye hamara model sirf age nahi dekhta, balki multi-signal verification karta hai. Agar package ka naam clean hai, typosquat distance normal hai, aur documentation mojood hai toh model usko 'Allow' ya 'Warn' mein rakhta hai, bina waja block nahi karta.")
    ]

    for q, a in qa:
        p_q = doc.add_paragraph()
        p_q.add_run(f"{q}\n").bold = True
        p_q.add_run(a)

    output_path = Path("D:/FYP/docs/PackGuard_AI_Risk_Layer_Guide.docx")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(output_path))
    print(f"DOCX created successfully at: {output_path}")

if __name__ == "__main__":
    create_guide_docx()
