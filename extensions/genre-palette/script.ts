/// <reference path="../../types/melovian-extension.d.ts" />
// Genre palette. The sandbox loads the compiled .js, then calls
// register(api). api.registerTrackRule adds one declarative rule per
// call. Network, storage, and DOM access are all blocked by the audit
// and the loader.

const PALETTE: Array<[string, string]> = [
  ["jazz", "#d4a017"],
  ["blues", "#3b6ea5"],
  ["classical", "#8e7cc3"],
  ["ambient", "#5f9ea0"],
  ["electronic", "#39c5cf"],
  ["techno", "#00b7a8"],
  ["house", "#e06666"],
  ["metal", "#8b0000"],
  ["punk", "#c2185b"],
  ["hip hop", "#7b8c2a"],
  ["rap", "#7b8c2a"],
  ["country", "#a05a2c"],
  ["folk", "#6d8b3c"],
  ["reggae", "#2e8b57"],
  ["soul", "#b5651d"],
  ["funk", "#cc5500"],
  ["rock", "#4a6fa5"],
  ["pop", "#e8599c"],
  ["soundtrack", "#5c4d7d"],
  ["lo-fi", "#a1887f"],
  ["synth-pop", "#f471ff"],
  ["chillwave", "#7fd8be"],
  ["drum and bass", "#ff7847"]
];

function register(api: melovian.ExtensionAPI): void {
  for (const [genre, color] of PALETTE) {
    api.registerTrackRule({
      match: { genreContains: genre },
      decoration: { progressColor: color }
    });
  }
}
