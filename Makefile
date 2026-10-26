PY ?= python3
export PYTHONPATH := src

.PHONY: test synthetic run-synthetic run-real clean-outputs

test:            ## run the full automated test-suite
	$(PY) -m unittest discover -s tests -t . -v

synthetic:       ## regenerate the synthetic TEST data (data/synthetic)
	$(PY) -m cffc generate-synthetic --root data/synthetic

run-synthetic:   ## run the 16-run matrix on SYNTHETIC data -> outputs/synthetic
	$(PY) -m cffc run --data-root data/synthetic --out-root outputs

run-real:        ## run the matrix on REAL evidence -> outputs/real (errors if data/real is empty)
	$(PY) -m cffc run --data-root data/real --out-root outputs

clean-outputs:
	rm -rf outputs/synthetic outputs/real
