import os
import sys
import pandas as pd
import numpy as np
import requests
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
from io import StringIO
import csv
import argparse
from scapy.all import rdpcap, IP, TCP, UDP
import time

class NetworkIntrusionDetectionSystem:
    def __init__(self, pcap_file=None, model_path=None):
        """Initialize the Network Intrusion Detection System."""
        self.pcap_file = pcap_file
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.malicious_ip_list = set()
        
    def get_service(self, packet):
        """Determine the service based on port numbers."""
        if TCP in packet or UDP in packet:
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            common_services = {80: "http", 443: "https", 22: "ssh", 53: "dns", 25: "smtp"}
            return common_services.get(port, "other")
        return "unknown"
    
    def get_flag(self, packet):
        """Extract TCP flags."""
        return packet.sprintf("%TCP.flags%") if TCP in packet else "other"
        
    def process_pcap(self):
        """Process the PCAP file and extract features."""
        print(f"Processing PCAP file: {self.pcap_file}")
        packets = rdpcap(self.pcap_file)
        data = []
        
        for packet in packets:
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = packet[IP].proto
                    src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else -1)
                    dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else -1)
                    packet_len = len(packet)

                    # Feature Extraction
                    duration = 0  # Placeholder for session tracking
                    protocol_type = {1: "icmp", 6: "tcp", 17: "udp"}.get(protocol, "other")
                    service = self.get_service(packet)
                    flag = self.get_flag(packet)
                    src_bytes = len(packet[IP].payload)
                    dst_bytes = 0  # Placeholder, needs further analysis
                    land = 1 if src_ip == dst_ip and src_port == dst_port else 0
                    wrong_fragment = packet[IP].frag if IP in packet else 0
                    urgent = packet[TCP].urgptr if TCP in packet else 0
                    hot = 0  # Attack-related activity placeholder
                    num_failed_logins = 0  # Needs session tracking
                    logged_in = 1 if service in ["ssh", "ftp", "telnet"] else 0
                    num_compromised = 0
                    root_shell = 0
                    su_attempted = 0
                    num_root = 0
                    num_file_creations = 0
                    num_shells = 0
                    num_access_files = 0
                    count = 1  # Placeholder for session tracking
                    srv_count = 1
                    serror_rate = 0
                    srv_serror_rate = 0
                    same_srv_rate = 1
                    diff_srv_rate = 0
                    dst_host_count = 1
                    dst_host_srv_count = 1

                    # Append extracted data
                    data.append([
                        src_ip, dst_ip, duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
                        wrong_fragment, urgent, hot, num_failed_logins, logged_in,
                        num_compromised, root_shell, su_attempted, num_root, num_file_creations,
                        num_shells, num_access_files, count, srv_count, serror_rate,
                        srv_serror_rate, same_srv_rate, diff_srv_rate, dst_host_count,
                        dst_host_srv_count
                    ])
            
            except Exception as e:
                pass  # Skip errors to ensure processing continues

        columns = [
            "src_ip", "dst_ip", "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
            "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
            "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "count", "srv_count", "serror_rate",
            "srv_serror_rate", "same_srv_rate", "diff_srv_rate", "dst_host_count",
            "dst_host_srv_count"
        ]

        # Convert extracted data into a DataFrame
        self.df_pcap = pd.DataFrame(data, columns=columns)
        print(f"Processed {len(self.df_pcap)} packets")
        return self.df_pcap
        
    def load_train_dataset(self):
        """Load the NSL-KDD dataset for training."""
        print("Loading training dataset...")
        url_dataset = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
        columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
            "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
            "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
            "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
            "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
            "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
            "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"]
            
        response = requests.get(url_dataset)
        data = StringIO(response.text)
        df = pd.read_csv(data, names=columns, nrows=50000)
        df.drop(columns=["difficulty"], inplace=True)
        
        # Encode Categorical Features
        categorical_columns = ["protocol_type", "service", "flag"]
        for col in categorical_columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            self.label_encoders[col] = le

        df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
        X = df.drop(columns=["label"])
        y = df["label"]
        
        # Save feature columns for later use
        self.feature_columns = X.columns
        
        return X, y
    
    def train_model(self, save_model=True):
        """Train the XGBoost model."""
        print("Training model...")
        X, y = self.load_train_dataset()
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Handle Class Imbalance using SMOTE
        smote = SMOTE(random_state=42)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        
        # Standardize Features
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)
        
        # Train XGBoost Model
        self.model = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        print(f"Model Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("Classification Report:\n", classification_report(y_test, y_pred))
        
        if save_model and self.model_path:
            import pickle
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                    'label_encoders': self.label_encoders,
                    'feature_columns': self.feature_columns
                }, f)
            print(f"Model saved to {self.model_path}")
            
        return self.model
    
    def load_model(self):
        """Load a pre-trained model."""
        if not os.path.exists(self.model_path):
            print(f"Model file {self.model_path} not found. Training a new model...")
            return self.train_model()
        
        print(f"Loading model from {self.model_path}")
        import pickle
        with open(self.model_path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.scaler = data['scaler']
            self.label_encoders = data['label_encoders']
            self.feature_columns = data['feature_columns']
        return self.model
    
    def get_malicious_ips(self):
        """Fetch a list of known malicious IPs."""
        print("Fetching malicious IP list...")
        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
            response = requests.get(url)
            if response.status_code == 200:
                self.malicious_ip_list = {line.strip() for line in response.text.split("\n") 
                                        if line and not line.startswith("#")}
                print(f"Loaded {len(self.malicious_ip_list)} malicious IPs")
                return self.malicious_ip_list
        except Exception as e:
            print(f"Error fetching malicious IPs: {e}")
        return set()
    
    def check_signature_based_detection(self, src_ip, dst_ip):
        """Check if an IP is in the malicious IP list."""
        return src_ip in self.malicious_ip_list or dst_ip in self.malicious_ip_list
    
    def generate_detectors(self, n_detectors, feature_size):
        """Generate detectors for the Artificial Immune System."""
        return np.random.uniform(-1, 1, size=(n_detectors, feature_size))
    
    def negative_selection_algorithm(self, X_test, detectors, threshold=0.15):
        """Implement the Negative Selection Algorithm for AIS."""
        y_pred = []
        for sample in X_test:
            anomaly_score = np.min(np.linalg.norm(detectors - sample, axis=1))
            y_pred.append(1 if anomaly_score > threshold else 0)
        return np.array(y_pred)
    
    def prepare_pcap_for_prediction(self):
        """Prepare the PCAP data for prediction."""
        df_custom = self.df_pcap.copy()
        categorical_columns = ["protocol_type", "service", "flag"]
        
        # Encode categorical features
        for col in categorical_columns:
            if col in df_custom.columns:
                df_custom[col] = df_custom[col].apply(
                    lambda x: self.label_encoders[col].transform([x])[0] 
                    if x in self.label_encoders[col].classes_ else -1
                )
        
        # Add missing columns with zero values
        missing_cols = set(self.feature_columns) - set(df_custom.columns)
        for col in missing_cols:
            df_custom[col] = 0
        
        # Ensure columns are in the same order as training data
        df_custom = df_custom[self.feature_columns]
        
        # Scale the features
        return self.scaler.transform(df_custom)
    
    def detect_intrusions(self, threshold=0.3):
        """Perform intrusion detection on the processed PCAP file."""
        if self.model is None:
            if self.model_path:
                self.load_model()
            else:
                self.train_model()
        
        # Fetch malicious IPs
        if not self.malicious_ip_list:
            self.get_malicious_ips()
        
        # Prepare data for prediction
        X_custom = self.prepare_pcap_for_prediction()
        
        # Predict using XGBoost
        prediction_probs = self.model.predict_proba(X_custom)[:, 1]
        predictions = (prediction_probs >= threshold).astype(int)
        
        # Calculate severity scores
        severity_scores = prediction_probs * 100
        responses = ["Monitor" if score < 40 else 
                    "Rate Limit" if score < 70 else 
                    "IP Block" for score in severity_scores]
        
        # Generate results
        results = []
        src_ips = self.df_pcap["src_ip"]
        dst_ips = self.df_pcap["dst_ip"]
        
        for i, pred in enumerate(predictions):
            src_ip = src_ips.iloc[i]
            dst_ip = dst_ips.iloc[i]
            signature_match = self.check_signature_based_detection(src_ip, dst_ip)
            
            severity_score = severity_scores[i]
            if pred == 1 or signature_match:
                severity = responses[i]
                status = "Attack"
                action = severity
            else:
                status = "Normal"
                action = "No Action"
                
            results.append({
                "packet_id": i+1,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "severity_score": severity_score,
                "status": status,
                "action": action,
                "signature_match": signature_match
            })
            
        return pd.DataFrame(results)
    
    def save_results(self, results, output_file="/results/intrusion_detection_results.csv"):
        """Save detection results to CSV file."""
        results.to_csv(output_file, index=False)
        print(f"✅ Intrusion detection results saved to {output_file}")
    def generate_and_serve_dashboard(self, results, host='localhost', port=9854):
        """Generate and directly serve a dashboard without saving to files first."""
        import http.server
        import socketserver
        import threading
        import webbrowser
        import matplotlib.pyplot as plt
        from io import BytesIO
        import base64

        # Calculate summary statistics
        total_packets = len(results)
        attack_count = len(results[results['status'] == 'Attack'])
        normal_count = total_packets - attack_count
        
        # Create figures
        plt.figure(figsize=(10, 6))
        
        # 1. Pie chart for traffic distribution
        plt.subplot(1, 2, 1)
        labels = ['Normal', 'Attack']
        sizes = [normal_count, attack_count]
        colors = ['#00CC96', '#EF553B']
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.axis('equal')
        plt.title('Traffic Distribution')
        
        # 2. Bar chart for actions (if attacks were detected)
        plt.subplot(1, 2, 2)
        if attack_count > 0:
            actions = results[results['status'] == 'Attack']['action'].value_counts()
            plt.bar(actions.index, actions.values, color=['#FFA15A', '#FF7F0E', '#EF553B'])
            plt.title('Action Distribution')
            plt.ylabel('Count')
        else:
            plt.bar(['No Attacks'], [1], color='#00CC96')
            plt.title('No Attacks Detected')
        
        # Save plot to a BytesIO object
        buf = BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png')
        buf.seek(0)
        
        # Convert plot to base64 for embedding in HTML
        img_str = base64.b64encode(buf.read()).decode('utf-8')
        
        # Generate HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Intrusion Detection Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .header {{ text-align: center; margin-bottom: 20px; color: #2a3f5f; }}
                .summary {{ margin-bottom: 20px; }}
                .summary table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                .summary th {{ background-color: #2a3f5f; color: white; text-align: left; padding: 12px; }}
                .summary td {{ border: 1px solid #ddd; padding: 12px; }}
                .charts {{ text-align: center; margin-top: 30px; }}
                .footer {{ margin-top: 30px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Network Intrusion Detection System Dashboard</h1>
                </div>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <table>
                        <tr>
                            <th>Metric</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Total Packets Analyzed</td>
                            <td>{total_packets}</td>
                        </tr>
                        <tr>
                            <td>Attacks Detected</td>
                            <td>{attack_count} ({attack_count/total_packets*100:.2f}%)</td>
                        </tr>
                        <tr>
                            <td>Normal Traffic</td>
                            <td>{normal_count} ({normal_count/total_packets*100:.2f}%)</td>
                        </tr>
        """
        
        # Add additional metrics if attacks were detected
        if attack_count > 0:
            avg_severity = results[results['status'] == 'Attack']['severity_score'].mean()
            max_severity = results[results['status'] == 'Attack']['severity_score'].max()
            
            html_content += f"""
                        <tr>
                            <td>Average Attack Severity</td>
                            <td>{avg_severity:.2f}%</td>
                        </tr>
                        <tr>
                            <td>Maximum Attack Severity</td>
                            <td>{max_severity:.2f}%</td>
                        </tr>
            """
            
        html_content += f"""
                    </table>
                </div>
                
                <div class="charts">
                    <h2>Visualizations</h2>
                    <img src="data:image/png;base64,{img_str}" alt="IDS Visualizations" style="max-width: 100%;">
                </div>
        """
        
        # Add top attacks section if attacks were detected
        if attack_count > 0:
            html_content += f"""
                <div class="summary">
                    <h2>Top 5 Most Severe Attacks</h2>
                    <table>
                        <tr>
                            <th>Packet ID</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Severity Score</th>
                            <th>Action</th>
                        </tr>
            """
            
            # Add rows for top 5 attacks
            top_attacks = results[results['status'] == 'Attack'].sort_values('severity_score', ascending=False).head(5)
            for _, attack in top_attacks.iterrows():
                html_content += f"""
                        <tr>
                            <td>{attack['packet_id']}</td>
                            <td>{attack['source_ip']}</td>
                            <td>{attack['destination_ip']}</td>
                            <td>{attack['severity_score']:.2f}%</td>
                            <td>{attack['action']}</td>
                        </tr>
                """
                
            html_content += """
                    </table>
                </div>
            """
            
        # Finish HTML document
        html_content += """
                <div class="footer">
                    <p>Network Intrusion Detection System Dashboard</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create a custom request handler to serve the HTML content directly
        class DashboardHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_content.encode())
                
            def log_message(self, format, *args):
                # Suppress log messages
                return
        
        # Create and start the server
        class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
        
        # Create the server
        server = ThreadedHTTPServer((host, port), DashboardHandler)
        
        # Start the server in a separate thread
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True  # Set as daemon so it will be killed when the main program exits
        server_thread.start()
        
        dashboard_url = f"http://{host}:{port}"
        print(f"\n🌐 Dashboard is now available at: {dashboard_url}")
        print(f"📊 Press Ctrl+C to stop the server")
        
        # Open the dashboard in the default web browser
        webbrowser.open(dashboard_url)
        
        return server, dashboard_url
        def visualize_results(self, results, output_dir="results", serve_http=True, host='localhost', port=8000):
            """Visualize detection results with HTML dashboard and optional HTTP server."""
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate HTML dashboard
            html_path = self.generate_html_dashboard(results, output_dir)
            
            if html_path and serve_http:
                # Serve the dashboard via HTTP
                server, url = self.serve_dashboard(html_path, host, port)
                return server, url
            
            return html_path
    def visualize_results(self, results, host='localhost', port=9854):
        """Visualize detection results with HTML dashboard served directly via HTTP."""
        try:
            # Generate and serve the dashboard directly
            server, dashboard_url = self.generate_and_serve_dashboard(results, host=host, port=port)
            
            return server, dashboard_url
        except Exception as e:
            print(f"Error visualizing results: {e}")
            return None, None
def main():
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('--pcap', required=True, help='Path to the PCAP file')
    parser.add_argument('--model', default='models/ids_model.pkl', help='Path to save/load the model')
    parser.add_argument('--output', default='intrusion_detection_results.csv', help='Output file for results')
    parser.add_argument('--train', action='store_true', help='Force training a new model')
    parser.add_argument('--threshold', type=float, default=0.3, help='Detection threshold (0-1)')
    parser.add_argument('--visualize', action='store_true', help='Generate visualization of results')
    parser.add_argument('--serve', action='store_true', help='Serve the dashboard via HTTP')
    parser.add_argument('--host', default='localhost', help='Host for the HTTP server')
    parser.add_argument('--port', type=int, default=8000, help='Port for the HTTP server')
    args = parser.parse_args()
    
    # Initialize the IDS
    ids = NetworkIntrusionDetectionSystem(pcap_file=args.pcap, model_path=args.model)
    
    # Process the PCAP file
    ids.process_pcap()
    
    # Train or load the model
    if args.train or not os.path.exists(args.model):
        ids.train_model()
    else:
        ids.load_model()
    
    # Detect intrusions
    results = ids.detect_intrusions(threshold=args.threshold)
    
    # Save results
    ids.save_results(results, output_file=args.output)
    
    # Visualize if requested
    http_server = None
    dashboard_url = None
    if args.visualize:
        http_server, dashboard_url = ids.visualize_results(
            results, host=args.host, port=args.port
        )
    
    # Print summary
    attack_count = len(results[results['status'] == 'Attack'])
    total_packets = len(results)
    print(f"\nIntrusion Detection Summary:")
    print(f"Total packets analyzed: {total_packets}")
    print(f"Attacks detected: {attack_count} ({attack_count/total_packets*100:.2f}%)")
    print(f"Normal traffic: {total_packets - attack_count} ({(total_packets - attack_count)/total_packets*100:.2f}%)")
    
    if attack_count > 0:
        print("\nTop 5 most severe attacks:")
        top_attacks = results[results['status'] == 'Attack'].sort_values('severity_score', ascending=False).head(5)
        for _, attack in top_attacks.iterrows():
            print(f"Packet {attack['packet_id']}: {attack['source_ip']} -> {attack['destination_ip']} | Severity: {attack['severity_score']:.2f}% | Action: {attack['action']}")
    if http_server and dashboard_url:
        try:
            print(f"\n🔍 Intrusion detection analysis complete!")
            print(f"📊 Interactive dashboard is available at: {dashboard_url}")
            print(f"Press Ctrl+C to stop the server and exit")
            
            # Keep the main thread running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping HTTP server...")
            http_server.shutdown()
            print("👋 Goodbye!")

if __name__ == "__main__":
    main()