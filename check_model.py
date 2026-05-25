import joblib

model = joblib.load("advanced_phishing_model.sav")

print("Model type:", type(model))

# Check number of features
try:
    print("Number of features expected:", model.n_features_in_)
except:
    print("Feature info not available")

# Check feature names (if stored)
try:
    print("Feature names:", model.feature_names_in_)
except:
    print("No feature names stored")

# Check classes
try:
    print("Classes:", model.classes_)
except:
    pass