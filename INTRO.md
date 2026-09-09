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

**Reasoner**: a program that read your facts + your OWL rules and *writes new triples into the graph*. Multiplied over a few hundred hosts and you have automatically discovered attack paths

**SPARQL**: the query language for asking questions of the graph. Very SQL-like on the surface.
It ssuperpower over SQL is *property paths* :`?a : connectsTo+ ?b` means "reachable in one or more hops" -> a recursive join, in three characters. That single feature is why a graph is the right tool here and a relational table isn't.

**FastAPI** : the thin HTTP layer on top, so the whole thing is a service other tools can call 

**T-Box/A-Box**: The T-Box is the schema (the classes and rules), the A-Box is the actual data. I keep them in seperate files. 