from pathlib import Path
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "KajovoCML_Onboarding_Catalog_2026.07.21.docx"
BLUE = RGBColor(0x2E, 0x74, 0xB5)
DARK_BLUE = RGBColor(0x1F, 0x4D, 0x78)
MUTED = RGBColor(0x5B, 0x65, 0x70)
LIGHT_BLUE = "E8EEF5"
TOTAL_DXA = 9360


def set_font(run, size=11, color=None, bold=None, italic=None):
    run.font.name = "Calibri"
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), "Calibri")
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), "Calibri")
    run.font.size = Pt(size)
    if color:
        run.font.color.rgb = color
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic


def set_cell_fill(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_cell_margins(cell, top=80, start=120, bottom=80, end=120):
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for edge, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{edge}"))
        if node is None:
            node = OxmlElement(f"w:{edge}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_table_geometry(table, widths):
    table.autofit = False
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    table_pr = table._tbl.tblPr
    tbl_w = table_pr.find(qn("w:tblW"))
    tbl_w.set(qn("w:w"), str(sum(widths)))
    tbl_w.set(qn("w:type"), "dxa")
    tbl_ind = table_pr.find(qn("w:tblInd"))
    if tbl_ind is None:
        tbl_ind = OxmlElement("w:tblInd")
        table_pr.append(tbl_ind)
    tbl_ind.set(qn("w:w"), "120")
    tbl_ind.set(qn("w:type"), "dxa")
    grid = table._tbl.tblGrid
    for child in list(grid):
        grid.remove(child)
    for width in widths:
        col = OxmlElement("w:gridCol")
        col.set(qn("w:w"), str(width))
        grid.append(col)
    for row in table.rows:
        for index, cell in enumerate(row.cells):
            cell.width = Inches(widths[index] / 1440)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            set_cell_margins(cell)
            tc_w = cell._tc.get_or_add_tcPr().find(qn("w:tcW"))
            tc_w.set(qn("w:w"), str(widths[index]))
            tc_w.set(qn("w:type"), "dxa")


def add_table(doc, headers, rows, widths):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.rows[0]._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
    for index, header in enumerate(headers):
        set_cell_fill(table.rows[0].cells[index], LIGHT_BLUE)
        p = table.rows[0].cells[index].paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        set_font(p.add_run(header), size=9.5, bold=True, color=DARK_BLUE)
    for row in rows:
        cells = table.add_row().cells
        for index, value in enumerate(row):
            p = cells[index].paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.15
            set_font(p.add_run(str(value)), size=9.5)
    set_table_geometry(table, widths)
    doc.add_paragraph().paragraph_format.space_after = Pt(0)
    return table


def add_heading(doc, text, level=1):
    p = doc.add_paragraph(style=f"Heading {level}")
    p.add_run(text)
    return p


def add_body(doc, text, bold_prefix=None):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.25
    if bold_prefix and text.startswith(bold_prefix):
        set_font(p.add_run(bold_prefix), bold=True)
        set_font(p.add_run(text[len(bold_prefix):]))
    else:
        set_font(p.add_run(text))
    return p


def configure_document(doc):
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = section.right_margin = section.bottom_margin = section.left_margin = Inches(1)
    section.header_distance = section.footer_distance = Inches(0.492)
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal._element.rPr.rFonts.set(qn("w:ascii"), "Calibri")
    normal._element.rPr.rFonts.set(qn("w:hAnsi"), "Calibri")
    normal.font.size = Pt(11)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.25
    for name, size, color, before, after in (
        ("Heading 1", 16, BLUE, 18, 10),
        ("Heading 2", 13, BLUE, 14, 7),
        ("Heading 3", 12, DARK_BLUE, 10, 5),
    ):
        style = doc.styles[name]
        style.font.name = "Calibri"
        style._element.rPr.rFonts.set(qn("w:ascii"), "Calibri")
        style._element.rPr.rFonts.set(qn("w:hAnsi"), "Calibri")
        style.font.size = Pt(size)
        style.font.color.rgb = color
        style.font.bold = True
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True
    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    set_font(header.add_run("KCML | Onboarding Catalog 2026.07.21"), size=9, color=MUTED)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(footer.add_run("COMPATIBLE IMPACT | katalogová změna MINOR"), size=8.5, color=MUTED)


def build():
    doc = Document()
    configure_document(doc)
    doc.add_paragraph().paragraph_format.space_after = Pt(90)
    kicker = doc.add_paragraph()
    kicker.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(kicker.add_run("KAJOVOCML - TECHNICKÝ KATALOG"), size=10, bold=True, color=BLUE)
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_after = Pt(8)
    set_font(title.add_run("Obecný komponentový model"), size=30, bold=True, color=DARK_BLUE)
    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.paragraph_format.space_after = Pt(24)
    set_font(subtitle.add_run("Onboarding Catalog 2026.07.21"), size=16, color=BLUE)
    lead = doc.add_paragraph()
    lead.alignment = WD_ALIGN_PARAGRAPH.CENTER
    lead.paragraph_format.space_after = Pt(80)
    set_font(lead.add_run("Kanonický model komponent, capabilities, pověření, oprávnění, auditních streamů a kompatibilních adaptérů."), size=11, italic=True, color=MUTED)
    add_table(doc, ["Vlastnost", "Hodnota"], [
        ("Dopad", "COMPATIBLE IMPACT"), ("Katalogová změna", "MINOR"), ("Release", "2026.07.21"),
        ("MCP protokol", "2025-11-25"), ("Lokalizace", "Čeština"),
    ], [2700, 6660])
    doc.add_page_break()

    add_heading(doc, "1. Účel a kompatibilita")
    add_body(doc, "Katalog 2026.07.21 zavádí komponentu jako jediný zdroj identity, KCML hostname, kategorie, registračního typu, role, vlastníka a oddělených stavů. Historické katalogy a migrace zůstávají neměnné.")
    add_body(doc, "Stávající MCP, managed-service, Kaja a onboarding rozhraní zůstávají funkční jako adaptéry. Deaktivace technicky zablokuje ingress, Pulse a egress, zvýší policy_epoch, ale nerevokuje dlouhodobé component credential.")
    add_heading(doc, "2. Komponentový kontrakt")
    add_table(doc, ["Oblast", "Kanonická pravidla"], [
        ("Identita", "UUID, KCML kód a výhradní kcmlNNNN.<domain> hostname"),
        ("Revize", "Manifest, digest, capabilities, protokoly, transporty a odvozené gates"),
        ("Autorizace", "OAuth client credentials, krátkodobé audience-bound tokeny a aktuální route/scope kontrola"),
        ("Stavy", "Lifecycle, activation, operational, monitoring a recertification jsou oddělené"),
        ("Audit", "Sekvenční stream, detekce mezer, replay, ACK a korelace"),
    ], [2200, 7160])
    add_heading(doc, "3. Kategorie")
    add_table(doc, ["Kategorie", "Role / použití"], [
        ("AI_CLIENT", "Klientský principal a spotřebitel capabilities"), ("AI_AGENT", "Agentní workflow a řízené tool scopes"),
        ("MCP_SERVER", "Povinný MCP modul a streamable HTTP transport"), ("MANAGED_RUNTIME", "Spravovaný výpočetní runtime"),
        ("EXTERNAL_SERVICE", "Externí služba dostupná pouze přes KCML gateway"), ("PLATFORM_SERVICE", "Řídicí, auditní, monitoring nebo bezpečnostní služba"),
    ], [2500, 6860])

    add_heading(doc, "4. Povinné aktivační gates")
    add_table(doc, ["Gate", "Podmínka aktivace"], [
        ("AUTHORIZATION", "Funkční OAuth a aktuální kontrola audience, scope a route"),
        ("PUBLIC_ENDPOINT", "Výhradní KCML hostname; alternativní host/IP/port/service name se odmítá"),
        ("TECHNICAL_DISABLE", "Ověřený mechanismus okamžitého zablokování ingress/Pulse/egress"),
        ("MONITORING", "Aktivní profil a zdravé povinné sondy"),
        ("AUDIT_CONTINUITY", "Dostupný souvislý stream bez nevyřešené mezery"),
    ], [2700, 6660])

    add_heading(doc, "5. Capability kontrakty")
    add_table(doc, ["Capability", "Protokol", "Požadavek"], [
        ("mcp.initialize", "MCP", "Povinné pro MCP_SERVER"),
        ("mcp.notifications.initialized", "MCP", "Povinné pro MCP_SERVER"),
        ("mcp.tools.list", "MCP", "Povinné pro MCP_SERVER"),
        ("mcp.tools.call", "MCP", "Povinné pro MCP_SERVER"),
        ("component.discovery", "HTTPS", "Discovery kontrakt"),
        ("component.pulse", "KCML Pulse", "Monitoring a provozní stav"),
        ("component.audit.write", "KCML Audit", "Sekvenční audit ingest"),
    ], [3900, 2100, 3360])

    doc.add_page_break()
    add_heading(doc, "6. Onboarding API v2")
    add_table(doc, ["Operace", "Endpoint", "Výsledek"], [
        ("Vytvořit", "POST /v2/component-onboardings", "Job a přidělená KCML identita"),
        ("Stav", "GET /v2/component-onboardings/{id}", "Aktuální stav a gates"),
        ("Revize", "POST /v2/component-onboardings/{id}/revisions", "Nová kanonická revize"),
        ("Readiness", "POST /v2/component-onboardings/{id}/readiness", "Vyhodnocení gates a claim token"),
        ("Credential", "POST /v2/component-onboardings/{id}/credential-claims", "Jednorázové zobrazení client secret"),
        ("Zrušit", "DELETE /v2/component-onboardings/{id}", "Auditované zrušení"),
    ], [1900, 4400, 3060])
    add_body(doc, "Component secret se neukládá v otevřené podobě. Uchovává se pouze HMAC digest a bezpečný fingerprint; rotace a revokace jsou explicitní operace.")

    add_heading(doc, "7. Autorizační důvody")
    add_table(doc, ["Stabilní kód", "Český význam"], [
        ("invalid_token", "Token není platný."), ("expired_token", "Platnost tokenu vypršela."),
        ("revoked_token", "Token nebo pověření bylo revokováno."), ("insufficient_scope", "Chybí požadovaný scope."),
        ("invalid_audience", "Audience nebo hostname neodpovídá cílové komponentě."), ("component_disabled", "Komponenta je deaktivovaná."),
        ("component_quarantined", "Komponenta je v karanténě."), ("route_denied", "Aktuální route oprávnění volání nepovoluje."),
        ("catalog_incompatible", "Revize komponenty není kompatibilní s aktuálním katalogem."),
    ], [3100, 6260])

    add_heading(doc, "8. Auditní rekonstrukce")
    add_body(doc, "Každá událost nese workflow a krok, iniciátora, čas, model/tool/službu, bezpečně klasifikované vstupy a výstupy, principal/fingerprint, scope/route rozhodnutí, protokolový výsledek, retry/idempotency, correlation/causation/trace/span, změnu stavu a verzi katalogu.")
    add_body(doc, "Přijaté sekvence jsou potvrzovány. Skok vytvoří GAP_DETECTED a replay požadavek od první chybějící sekvence. Nevyřešená mezera blokuje aktivaci; překročení grace limitu vede k bezpečnému odstavení nebo karanténě.")
    add_heading(doc, "9. Kompatibilitní matice")
    add_table(doc, ["Klient / artefakt", "2026.07.20", "2026.07.21"], [
        ("MCP blueprint", "Adaptér - podporováno", "Kanonický profil - podporováno"),
        ("AI/Kaja klient", "Adaptér - podporováno", "Komponentový principal - podporováno"),
        ("Managed service", "Adaptér - podporováno", "Kanonický profil - podporováno"),
        ("Manifest 1.4 / 1.5", "Pouze uložené/migrační", "Pouze uložené/migrační"),
        ("Manifest 2026.07.20", "Nový intake", "Kompatibilní adaptér"),
        ("Manifest 2026.07.21", "Není dostupný", "Nový intake"),
    ], [3000, 3000, 3360])
    add_heading(doc, "10. Provozní zásady")
    add_body(doc, "Gateway ověřuje Host, SNI a token audience. Interní runtime hop není zvenku adresovatelný. Autorizační rozhodnutí při každém volání čte aktuální databázový stav a aktuální route/scope oprávnění; dlouhá lokální cache se nepoužívá.")
    add_body(doc, "Retirement, deregistration, revokace, karanténa a monitoring failure jsou samostatné auditované operace. Žádná z nich není implicitním vedlejším účinkem prosté technické deaktivace.")

    doc.core_properties.title = "KajovoCML Onboarding Catalog 2026.07.21"
    doc.core_properties.subject = "Obecný komponentový model KCML"
    doc.core_properties.author = "KajovoCML"
    doc.core_properties.keywords = "KCML, component, onboarding, OAuth, audit"
    doc.save(OUTPUT)


if __name__ == "__main__":
    build()
