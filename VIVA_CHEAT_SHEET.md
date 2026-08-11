# Viva & Examination Cheat Sheet — AI Network Intrusion Detection

Quick 1–3 sentence answers to common faculty questions during viva and project review.

---

### Q1: What is your project?
**Answer:** Our project is an **AI-Powered Network Intrusion Detection System** that automatically analyzes network connection behavior and predicts whether a flow is normal (`BENIGN`) or a cyber attack using Machine Learning.

---

### Q2: What problem are you solving?
**Answer:** Modern networks process millions of connections that human security teams cannot inspect manually. Our system automatically screens traffic in real time and flags malicious activity so security teams can investigate faster.

---

### Q3: What is network intrusion?
**Answer:** Network intrusion is any unauthorized or malicious attempt to access, disrupt, or compromise a computer network, such as flooding servers with traffic or scanning open ports.

---

### Q4: What is network traffic?
**Answer:** Network traffic refers to data packets moving across a network between devices. We group these packets into **network flows** measured over time.

---

### Q5: What dataset did you use?
**Answer:** We used the benchmark **CIC-IDS2017 dataset**, which contains real-world captured network traffic with both normal background activity and realistic cyber attacks.

---

### Q6: What does one row represent in your dataset?
**Answer:** One row represents a single completed network flow session between a client and server, described by 78 numerical feature measurements.

---

### Q7: What are the 78 features?
**Answer:** They are mathematical measurements of network flow behavior, such as packet counts, flow duration, packet sizes, transmission rates, TCP flags, and idle times.

---

### Q8: Why do you need 78 features instead of just 1 or 2?
**Answer:** A single feature cannot distinguish between large legitimate file transfers and cyber attacks. Combining 78 behavioral measurements allows the AI to recognize complex attack signatures accurately.

---

### Q9: How did you clean the data?
**Answer:** We replaced infinite division values with column maximums, imputed missing values with column medians, removed zero-variance columns, and scaled features using `StandardScaler`.

---

### Q10: Which Machine Learning models did you compare?
**Answer:** We trained and compared **Logistic Regression**, **Random Forest**, and **XGBoost (Extreme Gradient Boosting)**.

---

### Q11: Why did you compare multiple models?
**Answer:** We compared them to find the best balance between multi-class accuracy, inference speed, and error rates across imbalanced attack categories.

---

### Q12: Which model is used for final prediction and why?
**Answer:** We chose **XGBoost** because it achieved the highest accuracy (`99.85%`) and fast sub-10ms prediction speed for real-time traffic screening.

---

### Q13: How does the model learn?
**Answer:** During training, XGBoost builds an ensemble of decision trees that learn statistical patterns from labeled normal and attack traffic examples.

---

### Q14: How does prediction happen for new network traffic?
**Answer:** The user enters flow measurements, FastAPI scales the 78 features using `StandardScaler`, XGBoost calculates class probabilities, and the highest probability class is displayed.

---

### Q15: What happens when new traffic comes in?
**Answer:** FastAPI validates the input format, normalizes the data, sends it to XGBoost for inference, and returns the threat label and confidence score within milliseconds.

---

### Q16: What is FastAPI?
**Answer:** FastAPI is a modern, high-performance Python web framework used to host machine learning models as production REST API endpoints.

---

### Q17: Why did you use FastAPI?
**Answer:** FastAPI is extremely fast, asynchronous, lightweight, automatically validates input data with Pydantic, and generates interactive API documentation (`/docs`).

---

### Q18: What is the use of the dashboard?
**Answer:** The dashboard provides a visual, presentation-ready interface for security analysts and faculty to test predictions, view system architecture, and review threat reports.

---

### Q19: What does BENIGN mean?
**Answer:** `BENIGN` means normal, safe network traffic with no malicious behavior detected.

---

### Q20: What does DDoS mean?
**Answer:** `DDoS` (Distributed Denial of Service) is a cyber attack where multiple compromised systems flood a target server with traffic to crash it.

---

### Q21: What does PortScan mean?
**Answer:** `PortScan` is a reconnaissance technique where an attacker systematically probes network ports to discover open services and vulnerabilities.

---

### Q22: How did you test the model?
**Answer:** We tested the model on an unseen 20% stratified test set and evaluated overall accuracy, precision, recall, and F1-score.

---

### Q23: What metrics did you achieve?
**Answer:** Our XGBoost model achieved **99.85% overall test accuracy**, 99.8% macro precision, and 0.998 macro F1-score on the CIC-IDS2017 dataset.

---

### Q24: What is data leakage?
**Answer:** Data leakage occurs when test set information accidentally leaks into the training phase, giving fake, unearned high accuracy scores.

---

### Q25: Did you check for data leakage?
**Answer:** Yes, we ran a dedicated 10-point audit script (`validation_audit.py`) to verify zero train/test overlap and ensure scaler transformations were fitted ONLY on training data.

---

### Q26: What is the real-world use of this project?
**Answer:** It functions as an automated screening layer in Security Operations Centers (SOCs) to flag suspicious connections and alert analysts before major security breaches occur.

---

### Q27: What are the limitations of your project?
**Answer:** The model predicts based on patterns learned from the CIC-IDS2017 dataset; novel, unseen attack methods or unparsed raw PCAP packets require additional upstream processing.

---

### Q28: If a faculty member asks: "Is this model 100% perfect?", what do you say?
**Answer:** No machine learning model is 100% perfect. Our system provides statistical probability scores to assist security analysts, who perform the final investigation on flagged threats.
