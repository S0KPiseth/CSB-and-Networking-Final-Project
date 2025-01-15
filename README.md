## Installing
1. **Clone repository**
   ```
   git clone https://github.com/S0KPiseth/CSB-and-Networking-Final-Project.git
   cd CSB-and-Networking-Final-Project
   ```
2. **Create a virtual environment:**
    ```sh
    python -m venv venv
    ```

3. **Activate the virtual environment:**
    ```sh
    venv\Scripts\activate
    ```
4. **Install requirement dependencies**
   ```
   pip install -r requirements.txt
   ```
5. **Run program**
   ```
   streamlit run CSB_FInal_project.py
   ```
# Convert PCAP to CSV using CICFlowMeter

CICFlowMeter is a powerful tool to extract network traffic features from PCAP files and save them in CSV format.

---

## Steps

### 1. Download and Install CICFlowMeter
1. Visit the [CICFlowMeter GitHub Repository](https://github.com/ahlashkari/CICFlowMeter).
2. Download the tool and install it by following the instructions provided on the repository.

---

### 2. Select Your PCAP File
- Use your own `.pcap` file or download the sample file from the [Input Sample folder](https://github.com/S0KPiseth/CSB-and-Networking-Final-Project/tree/main/Input%20sample).
- Ensure the PCAP file is properly captured and complete.

---

### 3. Run CICFlowMeter
1. Open **CICFlowMeter**.
2. **Input the PCAP File**:
   - Navigate to the input field and upload your `.pcap` file.
3. **Set the Output Directory**:
   - Choose the location where the resulting CSV file will be saved.

---

### 4. Extract Flows and Save as CSV
1. Start the conversion process by clicking **Start** or running the tool through the terminal if you are using the CLI version.
2. CICFlowMeter will generate flow-based features and save them in a CSV format at your specified output directory.

---

### 5. Verify the CSV File and use CSV file as a file input in the web app
- Navigate to your output directory and open the generated `.csv` file.
- Ensure that it contains the expected flow-based features for your analysis.
- Click upload in web interface and chose you CSV file.

---
