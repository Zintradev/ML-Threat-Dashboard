import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.feature_selection import SelectFromModel
import joblib
import re
import warnings
import os

warnings.filterwarnings('ignore')

print("✅ Librerías importadas")

class RealTrafficClassifier:
    """Clasificador optimizado para tráfico HTTP/HTTPS real"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.target_encoder = LabelEncoder()
        self.feature_selector = None
        self.is_trained = False
        
    def create_synthetic_training_data(self):
        """Crear datos de entrenamiento sintéticos basados en patrones reales"""
        print("🎯 Creando dataset de entrenamiento sintético...")
        
        normal_patterns = [
            {'method': 'GET', 'path': '/', 'status': 200, 'size': 1500},
            {'method': 'GET', 'path': '/index.html', 'status': 200, 'size': 2000},
            {'method': 'GET', 'path': '/images/logo.png', 'status': 200, 'size': 5000},
            {'method': 'POST', 'path': '/login', 'status': 200, 'size': 800},
            {'method': 'GET', 'path': '/products', 'status': 200, 'size': 3000}
        ]
        
        attack_patterns = {
            'sql_injection': [
                {'method': 'GET', 'path': "/search?q=' OR '1'='1", 'status': 200, 'size': 500},
                {'method': 'GET', 'path': "/admin'--", 'status': 200, 'size': 600},
                {'method': 'POST', 'path': '/login', 'status': 401, 'size': 400},
                {'method': 'GET', 'path': "/union select 1,2,3--", 'status': 200, 'size': 700}
            ],
            'xss': [
                {'method': 'GET', 'path': '/search?q=<script>alert(1)</script>', 'status': 200, 'size': 800},
                {'method': 'POST', 'path': '/comment', 'status': 200, 'size': 900},
                {'method': 'GET', 'path': '/?param=javascript:alert(1)', 'status': 200, 'size': 600}
            ],
            'path_traversal': [
                {'method': 'GET', 'path': '/../../etc/passwd', 'status': 404, 'size': 300},
                {'method': 'GET', 'path': '/..%2f..%2fwin.ini', 'status': 404, 'size': 350},
                {'method': 'GET', 'path': '/../../../config.php', 'status': 404, 'size': 400}
            ],
            'dos': [
                {'method': 'GET', 'path': '/', 'status': 200, 'size': 100},
                {'method': 'POST', 'path': '/api', 'status': 200, 'size': 50},
                {'method': 'GET', 'path': '/images/1.jpg', 'status': 200, 'size': 80}
            ]
        }
        
        data = []
        labels = []
        
        for _ in range(1000):
            pattern = normal_patterns[np.random.randint(0, len(normal_patterns))]
            features = self._extract_features_from_pattern(pattern, 'normal')
            data.append(features)
            labels.append('normal')
        
        for attack_type, patterns in attack_patterns.items():
            for _ in range(250):
                pattern = patterns[np.random.randint(0, len(patterns))]
                features = self._extract_features_from_pattern(pattern, attack_type)
                data.append(features)
                labels.append(attack_type)
        
        df = pd.DataFrame(data)
        return df, pd.Series(labels)
    
    def _extract_features_from_pattern(self, pattern, label):
        """Extraer características de un patrón de tráfico"""
        method = pattern['method']
        path = pattern['path']
        status = pattern['status']
        size = pattern['size']
        
        # Características basadas en el patrón
        features = {
            'method_encoded': self._encode_method(method),
            'path_length': len(path),
            'has_special_chars': int(any(c in path for c in ["'", '"', '<', '>', '(', ')', ';'])),
            'has_encoding': int('%' in path),
            'has_sql_keywords': int(any(kw in path.lower() for kw in ['select', 'union', 'insert', 'drop', 'or '])),
            'has_script_tags': int('<script' in path.lower()),
            'has_path_traversal': int(any(pt in path for pt in ['../', '..\\', 'etc/passwd'])),
            'status_code': status,
            'response_size': size,
            'is_error': int(status >= 400),
            'request_frequency': np.random.poisson(5),  # Frecuencia de requests
            'unique_paths_ratio': np.random.uniform(0.1, 1.0),
            'error_rate': np.random.uniform(0.0, 0.3) if label == 'normal' else np.random.uniform(0.1, 0.8)
        }
        
        return features
    
    def _encode_method(self, method):
        """Codificar método HTTP"""
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'HEAD': 4}
        return method_map.get(method, 5)
    
    def train_flexible_model(self):
        """Entrenar modelo con datos sintéticos y reales"""
        print("🤖 Entrenando modelo flexible...")
        
        # Crear datos de entrenamiento
        X_train, y_train = self.create_synthetic_training_data()
        
        # Procesamiento
        X_processed = self._preprocess_features(X_train)
        y_encoded = self.target_encoder.fit_transform(y_train)
        
        # Selección de características
        if X_processed.shape[1] > 10:
            print("🔍 Realizando selección de características...")
            self.feature_selector = SelectFromModel(
                RandomForestClassifier(n_estimators=50, random_state=42),
                threshold='median'
            )
            X_processed = self.feature_selector.fit_transform(X_processed, y_encoded)
            print(f"   Features seleccionados: {X_processed.shape[1]}")
        
        # Modelo
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        # Validación cruzada
        cv_scores = cross_val_score(self.model, X_processed, y_encoded, cv=5, scoring='accuracy')
        print(f"📊 Validación Cruzada: {cv_scores.mean():.3f} (±{cv_scores.std():.3f})")
        
        # Entrenamiento final
        self.model.fit(X_processed, y_encoded)
        self.is_trained = True
        
        print(f"✅ Modelo entrenado - {len(self.target_encoder.classes_)} clases")
        print(f"📋 Clases: {list(self.target_encoder.classes_)}")
        return self
    
    def _preprocess_features(self, X):
        """Preprocesar características"""
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 0:
            X_scaled = self.scaler.fit_transform(X)
            return X_scaled
        return X.values
    
    def save_model(self, filepath):
        """Guardar modelo entrenado"""
        if not self.is_trained:
            raise ValueError("No hay modelo entrenado para guardar.")
            
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'target_encoder': self.target_encoder,
            'feature_selector': self.feature_selector,
            'is_trained': self.is_trained
        }
        
        joblib.dump(model_data, filepath, compress=3)
        print(f"💾 Modelo guardado en: {filepath}")

if __name__ == "__main__":
    print("✅ Clasificador para tráfico real definido")
    
    # Entrenar modelo
    classifier = RealTrafficClassifier()
    classifier.train_flexible_model()
    
    # Guardar modelo
    # Asegurar que el directorio existe
    os.makedirs("../backend", exist_ok=True)
    classifier.save_model('real_traffic_model.pkl')
