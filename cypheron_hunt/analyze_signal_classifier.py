import torch
import sys
import base64

# Usage: python analyze_signal_classifier.py [pfad_zur_pt_datei]
def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_signal_classifier.py <signal_classifier.pt>")
        sys.exit(1)
    pt_path = sys.argv[1]
    print(f"[i] Lade Modell: {pt_path}\n")
    try:
        model = torch.load(pt_path, map_location="cpu")
    except Exception as e:
        print(f"[!] Fehler beim Laden: {e}")
        sys.exit(2)
    print("[i] Modell geladen.\n")
    print("[i] Modell-Typ:", type(model))
    print("[i] Dir(model):", dir(model))
    print("\n[i] Suche nach verdächtigen Strings/Flags/Base64:")
    def search_obj(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                search_obj(k)
                search_obj(v)
        elif isinstance(obj, (list, tuple, set)):
            for v in obj:
                search_obj(v)
        elif isinstance(obj, (str, bytes)):
            s = obj.decode() if isinstance(obj, bytes) else obj
            if "flag" in s.lower() or "thm{" in s or "tryhackme{" in s:
                print("[FLAG?]", s)
            try:
                decoded = base64.b64decode(s).decode()
                if "flag" in decoded.lower() or "thm{" in decoded or "tryhackme{" in decoded:
                    print("[BASE64-FLAG?]", decoded)
            except Exception:
                pass
    search_obj(model)
    print("\n[i] Suche in __dict__ (falls vorhanden):")
    if hasattr(model, "__dict__"):
        search_obj(model.__dict__)
    print("\n[i] Fertig.")

if __name__ == "__main__":
    main()
