import eval as evaluation


def test_materialise_marks_and_strips_the_vulnerable_line():
    text, targets = evaluation.materialise("a = 1\nb = eval(x)  #!\n")
    assert targets == {2} and "#!" not in text


def test_summarise_counts_what_the_llm_changes():
    real = {"real": True, "dismissed": False}
    noise_kept = {"real": False, "dismissed": False}
    noise_dropped = {"real": False, "dismissed": True}
    results = [("vuln_a", True, [real, noise_dropped], 1.0),
               ("vuln_b", True, [], 2.0),               # missed
               ("safe_c", False, [noise_kept], 3.0)]
    m = evaluation.summarise(results)
    assert m["scanners"]["recall"] == 0.5 and m["scanners"]["missed"] == ["vuln_b"]
    assert m["scanners"]["precision"] == 1 / 3 and m["with_llm"]["precision"] == 1 / 2
    assert (m["noise_dismissed"], m["noise_total"], m["real_dismissed"]) == (1, 2, 0)
    assert m["seconds"] == 2.0
