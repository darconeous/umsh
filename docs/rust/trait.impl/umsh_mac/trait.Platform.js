(function() {
    const implementors = Object.fromEntries([["umsh",[["impl&lt;R, CS, KV&gt; <a class=\"trait\" href=\"umsh/trait.Platform.html\" title=\"trait umsh::Platform\">Platform</a> for <a class=\"struct\" href=\"umsh/tokio_support/struct.TokioPlatform.html\" title=\"struct umsh::tokio_support::TokioPlatform\">TokioPlatform</a>&lt;R, CS, KV&gt;<div class=\"where\">where\n    R: Radio,\n    CS: CounterStore,\n    KV: KeyValueStore,</div>",0],["impl&lt;R, G, CS, KV&gt; <a class=\"trait\" href=\"umsh/trait.Platform.html\" title=\"trait umsh::Platform\">Platform</a> for <a class=\"struct\" href=\"umsh/embassy_support/struct.EmbassyPlatform.html\" title=\"struct umsh::embassy_support::EmbassyPlatform\">EmbassyPlatform</a>&lt;R, G, CS, KV&gt;<div class=\"where\">where\n    R: Radio,\n    G: <a class=\"trait\" href=\"https://docs.rs/rand_core/0.6.4/rand_core/trait.CryptoRng.html\" title=\"trait rand_core::CryptoRng\">CryptoRng</a>,\n    CS: CounterStore,\n    KV: KeyValueStore,</div>",0]]],["umsh_mac",[]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":59,"fragment_lengths":[945,16]}