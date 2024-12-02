import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import lime
import lime.lime_tabular
from streamlit_agraph import agraph, Node, Edge, Config
import joblib
from lime.lime_tabular import LimeTabularExplainer


model = joblib.load('model/my_model2.pkl')
scaler = joblib.load('model/scaler.pkl')
feature_columns = [
"Total Fwd Packet",
"Src Port",
"Protocol",
"Bwd Packet/Bulk Avg",
"Fwd Seg Size Min",
"Fwd Bytes/Bulk Avg",
"Fwd Header Length",
"Fwd Act Data Pkts",
"Dst Port",
"Total Length of Fwd Packet"
]

def change_columns_name(df):
    column_mapping = {
        'Flow ID': 'Flow ID',
        'Src IP': 'Source IP',
        'Src Port': 'Source Port',
        'Dst IP': 'Destination IP',
        'Dst Port': 'Destination Port',
        'Protocol': 'Protocol',
        'Timestamp': 'Timestamp',
        'Flow Duration': 'Flow Duration',
        'Tot Fwd Pkts': 'Total Fwd Packets',
        'Tot Bwd Pkts': 'Total Backward Packets',
        'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
        'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
        'Fwd Pkt Len Max': 'Fwd Packet Length Max',
        'Fwd Pkt Len Min': 'Fwd Packet Length Min',
        'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
        'Fwd Pkt Len Std': 'Fwd Packet Length Std',
        'Bwd Pkt Len Max': 'Bwd Packet Length Max',
        'Bwd Pkt Len Min': 'Bwd Packet Length Min',
        'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
        'Bwd Pkt Len Std': 'Bwd Packet Length Std',
        'Flow Byts/s': 'Flow Bytes/s',
        'Flow Pkts/s': 'Flow Packets/s',
        'Flow IAT Mean': 'Flow IAT Mean',
        'Flow IAT Std': 'Flow IAT Std',
        'Flow IAT Max': 'Flow IAT Max',
        'Flow IAT Min': 'Flow IAT Min',
        'Fwd IAT Tot': 'Fwd IAT Total',
        'Fwd IAT Mean': 'Fwd IAT Mean',
        'Fwd IAT Std': 'Fwd IAT Std',
        'Fwd IAT Max': 'Fwd IAT Max',
        'Fwd IAT Min': 'Fwd IAT Min',
        'Bwd IAT Tot': 'Bwd IAT Total',
        'Bwd IAT Mean': 'Bwd IAT Mean',
        'Bwd IAT Std': 'Bwd IAT Std',
        'Bwd IAT Max': 'Bwd IAT Max',
        'Bwd IAT Min': 'Bwd IAT Min',
        'Fwd PSH Flags': 'Fwd PSH Flags',
        'Bwd PSH Flags': 'Bwd PSH Flags',
        'Fwd URG Flags': 'Fwd URG Flags',
        'Bwd URG Flags': 'Bwd URG Flags',
        'Fwd Header Len': 'Fwd Header Length',
        'Bwd Header Len': 'Bwd Header Length',
        'Fwd Pkts/s': 'Fwd Packets/s',
        'Bwd Pkts/s': 'Bwd Packets/s',
        'Pkt Len Min': 'Min Packet Length',
        'Pkt Len Max': 'Max Packet Length',
        'Pkt Len Mean': 'Packet Length Mean',
        'Pkt Len Std': 'Packet Length Std',
        'Pkt Len Var': 'Packet Length Variance',
        'FIN Flag Cnt': 'FIN Flag Count',
        'SYN Flag Cnt': 'SYN Flag Count',
        'RST Flag Cnt': 'RST Flag Count',
        'PSH Flag Cnt': 'PSH Flag Count',
        'ACK Flag Cnt': 'ACK Flag Count',
        'URG Flag Cnt': 'URG Flag Count',
        'CWE Flag Count': 'CWE Flag Count',
        'ECE Flag Cnt': 'ECE Flag Count',
        'Down/Up Ratio': 'Down/Up Ratio',
        'Pkt Size Avg': 'Average Packet Size',
        'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
        'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
        'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
        'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
        'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
        'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
        'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
        'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
        'Subflow Fwd Pkts': 'Subflow Fwd Packets',
        'Subflow Fwd Byts': 'Subflow Fwd Bytes',
        'Subflow Bwd Pkts': 'Subflow Bwd Packets',
        'Subflow Bwd Byts': 'Subflow Bwd Bytes',
        'Init Fwd Win Byts': 'Init_Win_bytes_forward',
        'Init Bwd Win Byts': 'Init_Win_bytes_backward',
        'Fwd Act Data Pkts': 'act_data_pkt_fwd',
        'Fwd Seg Size Min': 'min_seg_size_forward',
        'Active Mean': 'Active Mean',
        'Active Std': 'Active Std',
        'Active Max': 'Active Max',
        'Active Min': 'Active Min',
        'Idle Mean': 'Idle Mean',
        'Idle Std': 'Idle Std',
        'Idle Max': 'Idle Max',
        'Idle Min': 'Idle Min',
        'Label': 'Label'
    }
    try:
        newdf = df.rename(columns=column_mapping)
    except Exception:
        newdf = df
    return newdf
def clean_input(data):
    data = data.fillna(0)
    data.replace([np.inf, -np.inf], 0, inplace=True)
    data.replace(np.nan, 0, inplace=True)
    feature_columns_mapping = {
    "Total Fwd Packets": "Total Fwd Packet",
    "Source Port": "Src Port",
    "Protocol": "Protocol",
    "Bwd Avg Bytes/Bulk": "Bwd Packet/Bulk Avg",
    "Fwd Packet Length Min": "Fwd Seg Size Min",
    "Fwd Avg Bytes/Bulk": "Fwd Bytes/Bulk Avg",
    "Fwd Header Length": "Fwd Header Length",
    "act_data_pkt_fwd": "Fwd Act Data Pkts",
    "Destination Port": "Dst Port",
    "Total Length of Fwd Packets": "Total Length of Fwd Packet"
    }
    df = data.rename(columns=feature_columns_mapping)
    df =df[feature_columns]
    df = scaler.fit_transform(df)
    return df

def predict_traffic(data):
    scaled_x =clean_input(data)
    preds = model.predict(scaled_x)
    preds_labels = (preds >= 0.5).astype(int)
    new_label = np.where(preds_labels == 0, "Benign", "Malicious")
    return new_label, scaled_x



def get_lime_explanation(model, instance):

    return "LIME explanation placeholder text"

def main():
    st.set_page_config(layout="wide", page_title="Network Traffic Classification")
    
    # Sidebar for file upload
    st.sidebar.title("Upload Network Data")
    uploaded_file = st.sidebar.file_uploader(
        "Choose a file", 
        type=['csv'],
        help="Upload network traffic data file"
    )
    
    # Initialize session state for data and logs
    if 'network_data' not in st.session_state:
        st.session_state.network_data = None
    
    if 'log_entries' not in st.session_state:
        st.session_state.log_entries = pd.DataFrame(columns=[
            'Source', 'Destination', 'Timestamp', 
            'Source Port', 'Destination Port', 
            'Protocol', 'Network Type', 'Status', 'Classification'
        ])
    
    # File processing
    if uploaded_file is not None:
        try:
            # Read the uploaded file
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                # Add logic for other file types if needed
                st.error("Unsupported file type")
                return
            df = change_columns_name(df)
            
            # Preprocess and predict
            st.session_state.network_data = df
            df=df.drop(['Label'], axis=1)
            
            # Predict classifications
            df['Classification'], scaled_x = predict_traffic(df)
            
            # Create log entries
            log_entries = df.copy()
            log_entries['Status'] = 'Pending'
            st.session_state.log_entries = log_entries

            source_ips = df['Source IP'].tolist()
            end_ips = df['Destination IP'].tolist()
            connections = list(zip(source_ips, end_ips))[:100]  # Only take the first 20 connections

            # Get unique IPs from the first 20 connections (source and destination)
            unique_ips = set([ip for connection in connections for ip in connection])
        
        except Exception as e:
            st.error(f"Error processing file: {e}")

    # Main tab layout
    tab1, tab2, tab3, tab4 = st.tabs([
        "Network Endpoints", 
        "Classification Overview", 
        "LIME Explanation", 
        "Network Logs"
    ])
    
    # Network Endpoints Tab
    with tab1:
        st.header("Network Endpoints")
        if st.session_state.network_data is not None:
            nodes = [Node(id=ip, label=ip) for ip in unique_ips]
            
            # Create edges from the first 20 connections
            edges = [Edge(source=src, target=dst) for src, dst in connections]
            
            # Configure AGraph
            config = Config(width=750, height=450, directed=False, nodeHighlightBehavior=False, staticGraph=True)
            agraph(nodes=nodes, edges=edges, config=config)
    
    # Classification Overview Tab
    with tab2:
        st.header("Traffic Classification")
        if st.session_state.network_data is not None:
            unique_predict, counts_predict = np.unique(df['Classification'], return_counts=True)
            
            # Plotly bar chart
            fig = px.bar(
                x=unique_predict, 
                y=counts_predict,
                labels={'x': 'Classification', 'y': 'Count'},
                color_discrete_sequence=['black'] 
            )
            st.plotly_chart(fig)
            
    
    # LIME Explanation Tab
    with tab3:
        st.header("LIME Explanation")
        if st.session_state.network_data is not None:

            sample_idx = st.text_input(label ="Select a sample for explanation")
            if sample_idx and sample_idx.isdigit():
                sample_idx = int(sample_idx)
                sample = scaled_x[sample_idx]

                # Generate LIME explanation
                explainer = LimeTabularExplainer(
                    scaled_x,
                    feature_names=feature_columns,
                    class_names=["Benign", "Malicious"],
                    discretize_continuous=True,
                )

                explanation = explainer.explain_instance(
                    data_row=sample, 
                    predict_fn=lambda x: np.hstack([(1 - model.predict(x)), model.predict(x)]), 
                    num_features=4
                )

                # Show the explanation in Streamlit
                st.subheader("LIME Explanation")
                html_explanation = explanation.as_html()
                # st.components.v1.html(html_explanation, height=1200, scrolling=True)
                custom_html = html_explanation.replace(
                    "<style>", 
                    "<style> body { font-size: 18px; } .lime { width: 100%; }"
                )

                st.components.v1.html(custom_html, height=200, scrolling=True)
            else:
                st.write("Invalid input")

    
    # Network Logs Tab
    with tab4:
        st.header("Network Traffic Logs")
        if not st.session_state.log_entries.empty:

            # Editable log entries
            edited_logs = st.data_editor(
                st.session_state.log_entries, 
                column_config={
                    "Status": st.column_config.SelectboxColumn(
                        "Status",
                        options=['Pending', 'Allowed', 'Blocked'],
                        default='Pending'
                    )
                },
                disabled=['Source', 'Destination', 'Timestamp', 'Source Port', 'Destination Port', 'Protocol', 'Network Type', 'Classification']
            )
            
            # Update session state
            #st.session_state.log_entries = edited_logs

if __name__ == "__main__":
    main()