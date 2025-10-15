import argparse, yaml, json, random
def score_item(txt):
    bad = [" delete"," put "," patch "," post ","drop table","rm -rf"," update "," insert "]
    s = 1.0
    t = txt.lower()
    for b in bad:
        if b in t:
            s = min(s, 0.2)
    if " get " in (" " + t + " "):
        s = max(s, 0.8)
    random.seed(42)
    return round(s, 3)
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    args = ap.parse_args()
    data = yaml.safe_load(open(args.inp, "r"))
    out = {}
    for vt, items in (data or {}).items():
        if isinstance(items, list):
            out[vt] = [score_item((i.get("payload","")+" "+i.get("name",""))) for i in items]
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print("Wrote", args.out)
if __name__ == "__main__":
    main()
