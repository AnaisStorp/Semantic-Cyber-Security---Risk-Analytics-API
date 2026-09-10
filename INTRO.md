**RDF** = Resource Description Framework
every fact is a senctence of exactly three parts : subject -> predicate -> object 
That's it, a triple 
```
:web01      :runs      :nginx_1_18
:nginx_1_18     :affectedBy     :CVE-2021-23017
:web01      :connectsTo     :db01
```

A set of triples is a graph : the subjects and objects are the nodes, the predicates are the labelled edges. This is why it's called knowledge graph 

**Turtle** (.ttl) = the human-readable text format for writing those triples down

**OWL**: a vocabulary for describing the rules of your world, also written as triples. For example: "`connectsTo` is a *transitive* property" or: "Every `Host` that runs `Software` that is `affectedBy` a `Vulnerability` is a `VulnerabloeHost`"

**OWL RL**(Web Ontology Language, Rule Language) is monotonic and value-blind. It can compose relationships, but it cannot express "if the CVSS score exceeds 7.0 and the attack vector is Network and the target zone is internet-facing, then this is a viable attack step". Conditions on literal values, arithmetic, and negation are all outside the profile deliberately because they're what make reasoning undecidable or slow. 
-> An OWL reasoner materialises the structural closure over which SPARQL rules derive attack steps 

**Reasoner**: a program that read your facts + your OWL rules and *writes new triples into the graph*. Multiplied over a few hundred hosts and you have automatically discovered attack paths

**SPARQL**: the query language for asking questions of the graph. Very SQL-like on the surface.
It ssuperpower over SQL is *property paths* :`?a : connectsTo+ ?b` means "reachable in one or more hops" -> a recursive join, in three characters. That single feature is why a graph is the right tool here and a relational table isn't.

**FastAPI** : the thin HTTP layer on top, so the whole thing is a service other tools can call 

**T-Box/A-Box**: The T-Box is the schema (the classes and rules), the A-Box is the actual data. I keep them in seperate files .

#### four basic ideas 

1. an ontology is itself just triples : there is no special "schema language". You declare `scs:Host a owl:Class`(subject, predictae, obejct). The same format as the data. That is the whole trick of RDF/OWL and its hwy a graph can carry its own schema 
2. `rdfs:sdomain`is NOT a constraint -> its an INFERENCE RULE. This triped me up at first. If you write `scs:runs rdfs:doamin scs:Host` and then state `scs:printer_42 scs:runs scs:cups` the reasoner does not reject it. It concludes `scs:rpinter_42 a scs:Host`. RDF makes the open-world assumption : unstated things are unknown, not false. So domain/range are for deriving types not validation input 
3. A property chain is where inference stops being a party trick. You will state that a host runs a service, that the service uses a piece of software, and that the software is affected by a CVE. You will never state that the host has a vulnerability. The reasoner derives it from the chain. That single axiom is the difference between an asset inventory and a risk-analysis system.
4. Transivity gives reachability gratis : `connectsTo` is a direct network edge. `canReach` is its transitive super-property. State ten firewall rules, get the full reachability closure —> including the path through three hops that no human noticed.
