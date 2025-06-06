# 🚨 Cybersecurity Web Threat Detection Dashboard

import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

# Streamlit UI setup
st.set_page_config(page_title="Cybersecurity Threat Dashboard", layout="wide")
st.title("🚨 Cybersecurity Web Threat Detection Dashboard")

# File uploader
uploaded_file = st.file_uploader("📁 Upload your CloudWatch Traffic CSV", type=["csv"])

if uploaded_file:
    # Load dataset
    df = pd.read_csv(uploaded_file)

    # Preprocess time columns
    df['creation_time'] = pd.to_datetime(df['creation_time'], errors='coerce')
    df['end_time'] = pd.to_datetime(df['end_time'], errors='coerce')
    df['time'] = pd.to_datetime(df['time'], errors='coerce')
    df['src_ip_country_code'] = df['src_ip_country_code'].str.upper()

    # Feature engineering
    df['duration_seconds'] = (df['end_time'] - df['creation_time']).dt.total_seconds()
    df['avg_packet_size'] = (df['bytes_in'] + df['bytes_out']) / df['duration_seconds']
    df = df.dropna(subset=['duration_seconds', 'avg_packet_size'])

    # Show data
    st.subheader("📄 Sample of Uploaded Data")
    st.dataframe(df.head())

    # Country-wise traffic
    st.subheader("🌍 Country-wise Traffic Distribution")
    st.bar_chart(df['src_ip_country_code'].value_counts())

    # Anomaly Detection
    st.subheader("🧠 Anomaly Detection (Isolation Forest)")
    features = df[['bytes_in', 'bytes_out', 'duration_seconds', 'avg_packet_size']]
    model = IsolationForest(contamination=0.05, random_state=42)
    df['anomaly'] = model.fit_predict(features)
    df['anomaly'] = df['anomaly'].map({1: 'Normal', -1: 'Suspicious'})

    # Show anomaly results
    st.dataframe(df[['src_ip', 'dst_ip', 'bytes_in', 'bytes_out', 'anomaly']].head())

    # Visualize anomalies
    st.subheader("📊 Bytes In vs Bytes Out (with Anomaly Labels)")
    fig, ax = plt.subplots()
    sns.scatterplot(data=df, x='bytes_in', y='bytes_out', hue='anomaly',
                    palette={'Normal': 'green', 'Suspicious': 'red'}, ax=ax)
    plt.title('Anomaly Detection Visualization')
    st.pyplot(fig)

    # Suspicious country distribution
    st.subheader("🚩 Suspicious Sessions by Country")
    suspicious_by_country = df[df['anomaly'] == 'Suspicious']['src_ip_country_code'].value_counts()
    st.bar_chart(suspicious_by_country)

    # Live Prediction
    st.subheader("🔎 Test Live Traffic Session")

    b_in = st.number_input("Bytes In", value=1000)
    b_out = st.number_input("Bytes Out", value=1000)
    duration = st.number_input("Session Duration (seconds)", value=600.0)

    if st.button("Predict"):
        if duration == 0:
            st.error("⚠️ Session duration cannot be zero. Please enter a valid session duration.")
        elif b_in == 0 and b_out == 0:
            st.warning("⚠️ No data transferred. This session is suspicious.")
            st.markdown("### Prediction: <span style='color:red'>Suspicious</span>", unsafe_allow_html=True)
        else:
            avg_pkt = (b_in + b_out) / duration
            pred = model.predict([[b_in, b_out, duration, avg_pkt]])[0]
            result = "Suspicious" if pred == -1 else "Normal"
            color = "red" if result == "Suspicious" else "green"
            st.markdown(f"### Prediction: <span style='color:{color}'>{result}</span>", unsafe_allow_html=True)

else:
    st.info("👈 Please upload your AWS CloudWatch CSV file to begin analysis.")
