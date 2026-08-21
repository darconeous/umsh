+++
title = "Regions"
description = "Inspect the compiled UMSH region database on a map: what covers a position, and why."
template = "regions-map.html"
weight = 5
+++

## What this shows

A UMSH repeater can be told which regions it should accept traffic for. The
region database turns a position into that list, and this page is how the
database gets checked: click anywhere and it answers with every region
covering that point, the radio strings a repeater would be configured with,
the 16-bit codes those encode to, and which region it suggests as the packet
default.

The answer comes from the same code the phone runs, reading the same file it
downloads. Both are held to a shared set of conformance fixtures, so a
disagreement between this map and a radio is a test failure rather than a
surprise.

## Reading the result

A region is **core** when the position is inside it, and **expanded** when
only its margin reaches — every generated region carries a small outward
margin so a repeater near a border learns about both sides. The map draws
each layer in its own color; a position commonly sits in several at once,
because an airport region, a metro area, a state, and a country are
independent questions with independent answers.

Codes are deduplicated on the way to the radio. Where an airport and a metro
area share an IATA code, both appear as semantic matches and the radio is
given one entry.

## Where the data comes from

Airport and location data is OurAirports; country regions are jurisdiction
areas — land plus exclusive economic zone — from Marine Regions; US states
are Census TIGER/Line; the coastlines and borders drawn underneath are
Natural Earth. Every source, with its license, is listed in the panel beside
the map. The full pipeline and its policy choices live in `regions/` in the
repository.
