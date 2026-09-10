#  TURTLE CHEAT SHEET


# The prefixes: WHO says the word 
@prefix scs:  <https://anaisstorp.github.io/scsra/ontology#> .
#   The namespace. Every word we invented: Host, runs, affectedBy, cvssScore.
#   No logical power on its own — it is our private dictionary.

@prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
#   RDF core. Basically only rdf:type, abbreviated as "a".

@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
#   RDF SCHEMA = the simple hierarchy layer.
#   Words for "is a kind of" and "what this arrow connects":
#     rdfs:subClassOf     Host is a kind of Asset
#     rdfs:subPropertyOf  connectsTo is a kind of canReach
#     rdfs:domain         where this arrow STARTS  (asserts a type!)
#     rdfs:range          where this arrow ENDS    (asserts a type!)
#     rdfs:label          human name — no logic
#     rdfs:comment        human note — no logic

@prefix owl:  <http://www.w3.org/2002/07/owl#> .
#   WEB ONTOLOGY LANGUAGE = the real logic layer, on top of rdfs.
#   Declarations:
#     owl:Class, owl:ObjectProperty (→node), owl:DatatypeProperty (→literal),
#     owl:NamedIndividual, owl:Ontology
#   Rules (these generate new triples):
#     owl:TransitiveProperty    a→b, b→c  ⟹  a→c
#     owl:SymmetricProperty     a→b       ⟹  b→a
#     owl:inverseOf             a p b     ⟹  b q a
#     owl:disjointWith          overlap   ⟹  contradiction
#     owl:propertyChainAxiom    walk 3 arrows ⟹ draw 1 shortcut arrow
#     owl:Restriction + owl:onProperty + owl:someValuesFrom
#                               "the class of things having ≥1 such arrow"

@prefix xsd:     <http://www.w3.org/2001/XMLSchema#> .   # datatypes: string, decimal, date
@prefix dcterms: <http://purl.org/dc/terms/> .           # file metadata — no logic
@prefix skos:    <http://www.w3.org/2004/02/skos/core#> . # definitions — no logic

# Rule of thumb:  rdfs: = hierarchy   |   owl: = logic   |   scs: = our vocabulary
# rdfs and owl are read by the reasoner. scs words are only nodes it moves through.


# The syntax 
ex:thing  a          ex:Class ;           # "is a"        — declaration
          ex:arrow   ex:otherThing ;      # → resource    — you can keep walking
          ex:value   "text"@en ;          # → literal     — dead end
          ex:number  "7.7"^^xsd:decimal . # typed literal, "." ends it

#  ;  = same subject, next predicate
#  ,  = same subject + predicate, next object
#  .  = done
#  a  = rdf:type
#  #  = comment
#  [ ] = blank node (unnamed thing)
#  ( ) = ordered list


# Every line is one of three kinds 
# 1. DECLARATION   scs:Host a owl:Class .              → does nothing alone
# 2. DOCUMENTATION rdfs:label "Host"@en .              → reasoner ignores it
# 3. AXIOM         scs:canReach a owl:TransitiveProperty .  → CREATES NEW TRIPLES
#    Only category 3 does any work. In our file that's ~15 lines out of 200.