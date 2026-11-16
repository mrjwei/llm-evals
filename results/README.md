# results/

`cjp results build` writes the paper's figures and tables here (`tables/*.csv`, `figures/*.png`, `manifest.json`) from the canonical runs pinned in [`canonical.yaml`](canonical.yaml). It makes no API calls.

The built results are **not published yet**. The paper is being prepared for a conference submission, and they will be added here once it is out. The figure and table set they come from is listed in `canonical.yaml`.

`tables/H1_heuristic.csv` is shipped **unscored**: it is the hand-filled template for the heuristic review of the Triage UI. Its 11 criteria are quoted from Okazawa et al., Table I (the source the build checks against).
