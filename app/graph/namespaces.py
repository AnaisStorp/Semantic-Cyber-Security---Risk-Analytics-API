"""RDF namespaces used across the project
A namespace object turns an IRI prefix into something you can index:
    SCS.Host  -> URIRef("https://.../ontology#Host)
it is the python equivalent of a @prefix line in Turtle"""

from rdflib import Namespace

# rdflib is the RDF toolkit: it parses/serialises Turtle, stores triples and
# runs SPARQL. `namespace`is a tiny helper class, a string subclass whose
# attribute and item access concatenate onto the base IRI. SCS.Host and
# SCS["Host"] both build the full IRI.

# our own vocal
# these must match the @prefix in our .ttl

SCS = Namespace("https://anaisstorp.github.io/scsra/ontology#")
CORP = Namespace("https://anaisstorp.github.io/scsra/data#")

# prefix map used when serialisung output
# purely cosmetic : it makes exportes Turtle and Sparql results print

PREFIX_MAP = {
    "scs": SCS,
    "corp": CORP,
}
