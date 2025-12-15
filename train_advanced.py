import pandas as pd
import numpy as np
import pickle
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
import matplotlib.pyplot as plt
import seaborn as sns

class AdvancedModelTrainer:
    def __init__(self):
        self.models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Gradient Boosting': GradientBoostingClassifier(random_state=42),
            'AdaBoost': AdaBoostClassifier(random_state=42),
            'Decision Tree': DecisionTreeClassifier(random_state=42),
            'SVM': SVC(probability=True, random_state=42),
            'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000)
        }
        
        self.best_model = None
        self.scaler = StandardScaler()
        self.feature_importance = None
        
    def load_dataset(self):
        """Load the dataset from Hawk's advanced_dataset.csv"""
        try:
            df = pd.read_csv('advanced_dataset.csv')
            print(f"✓ Dataset loaded: {len(df)} records")
            print(f"✓ Features: {len(df.columns) - 2}")  # Subtract URL and label columns
            
            # Check if dataset has required columns
            if 'label' not in df.columns:
                print("✗ Error: 'label' column not found in dataset")
                return None
            
            return df
            
        except FileNotFoundError:
            print("✗ Error: advanced_dataset.csv not found!")
            print("  Please run feature_extractor_advanced.py first to create the dataset.")
            return None
        except Exception as e:
            print(f"✗ Error loading dataset: {e}")
            return None
    
    def prepare_data(self, df):
        """Prepare data for training"""
        # Separate features and target
        X = df.drop(['url', 'label'], axis=1, errors='ignore')
        y = df['label']
        
        # Handle any missing values
        X = X.fillna(0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"\nData Preparation:")
        print(f"  Training samples: {X_train.shape[0]}")
        print(f"  Testing samples: {X_test.shape[0]}")
        print(f"  Features: {X_train.shape[1]}")
        print(f"  Class distribution - Training: {np.bincount(y_train)}")
        print(f"  Class distribution - Testing: {np.bincount(y_test)}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test, X.columns
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train and evaluate multiple models"""
        results = {}
        
        print("\n" + "=" * 60)
        print("MODEL TRAINING AND EVALUATION")
        print("=" * 60)
        
        for name, model in self.models.items():
            print(f"\nTraining {name}...")
            
            try:
                # Train model
                model.fit(X_train, y_train)
                
                # Predictions
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                report = classification_report(y_test, y_pred, output_dict=True)
                
                if y_pred_proba is not None:
                    auc = roc_auc_score(y_test, y_pred_proba)
                else:
                    auc = None
                
                # Cross-validation
                cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
                
                # Store results
                results[name] = {
                    'model': model,
                    'accuracy': accuracy,
                    'precision': report['weighted avg']['precision'],
                    'recall': report['weighted avg']['recall'],
                    'f1_score': report['weighted avg']['f1-score'],
                    'auc': auc,
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std()
                }
                
                print(f"  Accuracy: {accuracy:.4f}")
                print(f"  F1-Score: {report['weighted avg']['f1-score']:.4f}")
                print(f"  CV Accuracy: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")
                if auc:
                    print(f"  AUC-ROC: {auc:.4f}")
                    
            except Exception as e:
                print(f"  Error training {name}: {str(e)[:100]}")
                continue
        
        return results
    
    def select_best_model(self, results):
        """Select the best model based on multiple metrics"""
        if not results:
            print("✗ No models were successfully trained!")
            return None
        
        print("\n" + "=" * 60)
        print("MODEL COMPARISON")
        print("=" * 60)
        
        # Create comparison DataFrame
        comparison = []
        for name, metrics in results.items():
            comparison.append({
                'Model': name,
                'Accuracy': metrics['accuracy'],
                'F1-Score': metrics['f1_score'],
                'AUC-ROC': metrics['auc'] if metrics['auc'] else 0,
                'CV Accuracy': metrics['cv_mean'],
                'CV Std': metrics['cv_std']
            })
        
        df_comparison = pd.DataFrame(comparison)
        df_comparison = df_comparison.sort_values('F1-Score', ascending=False)
        
        print("\nModel Performance Comparison:")
        print(df_comparison.to_string(index=False))
        
        # Select best model (based on F1-Score)
        best_model_name = df_comparison.iloc[0]['Model']
        self.best_model = results[best_model_name]['model']
        
        print(f"\n✅ Best Model: {best_model_name}")
        print(f"   F1-Score: {df_comparison.iloc[0]['F1-Score']:.4f}")
        print(f"   Accuracy: {df_comparison.iloc[0]['Accuracy']:.4f}")
        
        return best_model_name
    
    def evaluate_best_model(self, X_test, y_test, feature_names):
        """Evaluate the best model in detail"""
        if self.best_model is None:
            print("✗ No best model selected!")
            return
        
        print("\n" + "=" * 60)
        print("DETAILED EVALUATION OF BEST MODEL")
        print("=" * 60)
        
        # Predictions
        y_pred = self.best_model.predict(X_test)
        y_pred_proba = self.best_model.predict_proba(X_test)[:, 1]
        
        # Detailed metrics
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Good', 'Malicious']))
        
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print(f"AUC-ROC: {roc_auc_score(y_test, y_pred_proba):.4f}")
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"True Negatives: {cm[0, 0]}")
        print(f"False Positives: {cm[0, 1]}")
        print(f"False Negatives: {cm[1, 0]}")
        print(f"True Positives: {cm[1, 1]}")
        
        # Feature Importance (if available)
        if hasattr(self.best_model, 'feature_importances_'):
            self.feature_importance = pd.DataFrame({
                'feature': feature_names,
                'importance': self.best_model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print("\nTop 10 Most Important Features:")
            print(self.feature_importance.head(10).to_string(index=False))
    
    def save_model(self):
        """Save the trained model and scaler"""
        if self.best_model is None:
            print("✗ Cannot save: No model trained!")
            return False
        
        try:
            # Save model
            with open('advanced_model.pkl', 'wb') as f:
                pickle.dump({
                    'model': self.best_model,
                    'scaler': self.scaler,
                    'feature_importance': self.feature_importance
                }, f)
            
            print(f"\n✅ Model saved to: advanced_model.pkl")
            
            # Also save feature importance separately
            if self.feature_importance is not None:
                self.feature_importance.to_csv('feature_importance.csv', index=False)
                print(f"✅ Feature importance saved to: feature_importance.csv")
            
            return True
            
        except Exception as e:
            print(f"✗ Error saving model: {e}")
            return False
    
    def plot_results(self, X_test, y_test):
        """Plot evaluation metrics"""
        if self.best_model is None:
            return
        
        try:
            # Create subplots
            fig, axes = plt.subplots(2, 2, figsize=(12, 10))
            
            # 1. Confusion Matrix Heatmap
            y_pred = self.best_model.predict(X_test)
            cm = confusion_matrix(y_test, y_pred)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                       xticklabels=['Good', 'Malicious'],
                       yticklabels=['Good', 'Malicious'],
                       ax=axes[0, 0])
            axes[0, 0].set_title('Confusion Matrix')
            axes[0, 0].set_ylabel('True Label')
            axes[0, 0].set_xlabel('Predicted Label')
            
            # 2. Feature Importance (if available)
            if self.feature_importance is not None:
                top_features = self.feature_importance.head(10)
                axes[0, 1].barh(range(len(top_features)), top_features['importance'])
                axes[0, 1].set_yticks(range(len(top_features)))
                axes[0, 1].set_yticklabels(top_features['feature'])
                axes[0, 1].set_title('Top 10 Feature Importance')
                axes[0, 1].set_xlabel('Importance')
                axes[0, 1].invert_yaxis()
            
            # 3. ROC Curve
            from sklearn.metrics import roc_curve
            y_pred_proba = self.best_model.predict_proba(X_test)[:, 1]
            fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            axes[1, 0].plot(fpr, tpr, color='darkorange', lw=2)
            axes[1, 0].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            axes[1, 0].set_xlim([0.0, 1.0])
            axes[1, 0].set_ylim([0.0, 1.05])
            axes[1, 0].set_xlabel('False Positive Rate')
            axes[1, 0].set_ylabel('True Positive Rate')
            axes[1, 0].set_title(f'ROC Curve (AUC = {roc_auc_score(y_test, y_pred_proba):.4f})')
            axes[1, 0].grid(True)
            
            # 4. Class Distribution
            unique, counts = np.unique(y_test, return_counts=True)
            axes[1, 1].pie(counts, labels=['Good', 'Malicious'], autopct='%1.1f%%',
                          colors=['lightgreen', 'lightcoral'])
            axes[1, 1].set_title('Class Distribution in Test Set')
            
            plt.tight_layout()
            plt.savefig('model_evaluation_plots.png', dpi=100, bbox_inches='tight')
            plt.close()
            
            print(f"✅ Evaluation plots saved to: model_evaluation_plots.png")
            
        except Exception as e:
            print(f"⚠ Could not generate plots: {e}")

def main():
    print("=" * 60)
    print("HAWK - Advanced Model Trainer")
    print("=" * 60)
    
    # Initialize trainer
    trainer = AdvancedModelTrainer()
    
    # Load dataset
    df = trainer.load_dataset()
    if df is None:
        return
    
    # Prepare data
    X_train, X_test, y_train, y_test, feature_names = trainer.prepare_data(df)
    
    # Train and evaluate models
    results = trainer.train_models(X_train, X_test, y_train, y_test)
    
    # Select best model
    best_model_name = trainer.select_best_model(results)
    
    if best_model_name:
        # Evaluate best model
        trainer.evaluate_best_model(X_test, y_test, feature_names)
        
        # Save model
        if trainer.save_model():
            # Generate plots
            trainer.plot_results(X_test, y_test)
            
            print("\n" + "=" * 60)
            print("✅ TRAINING COMPLETE!")
            print("=" * 60)
            print("\nGenerated Files:")
            print("  - advanced_model.pkl (Trained model)")
            print("  - feature_importance.csv (Feature rankings)")
            print("  - model_evaluation_plots.png (Evaluation visualizations)")
            print("\nNext: Run final_app.py to use the trained model!")
            print("=" * 60)
    
    else:
        print("\n✗ Training failed. Please check your dataset.")

if __name__ == "__main__":
    main()