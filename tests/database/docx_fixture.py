from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile


DOCUMENT = """<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
  <w:p><w:pPr><w:outlineLvl w:val="0"/></w:pPr><w:r><w:t>差旅</w:t></w:r></w:p>
  <w:p><w:pPr><w:pStyle w:val="Section"/></w:pPr><w:r><w:t>住宿</w:t></w:r></w:p>
  <w:p><w:r><w:t>不得</w:t></w:r><w:r><w:t>报销</w:t><w:tab/><w:t>除非书面批准</w:t><w:br/><w:t>按实际金额。</w:t></w:r></w:p>
  <w:p><w:pPr><w:pStyle w:val="Section"/></w:pPr><w:r><w:t>住宿</w:t></w:r></w:p>
  <w:p><w:r><w:t>仅限正式员工。</w:t></w:r></w:p>
  <w:sectPr/>
</w:body>
</w:document>"""
STYLES = """<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:styleId="Base"><w:pPr><w:outlineLvl w:val="1"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Section"><w:basedOn w:val="Base"/></w:style>
</w:styles>"""
CONTENT_TYPES = """<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
 <Default Extension="xml" ContentType="application/xml"/>
 <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
 <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""
ROOT_RELS = """<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
DOCUMENT_RELS = """<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""


def docx_package(document=DOCUMENT, *, styles=STYLES, document_rels=DOCUMENT_RELS, root_rels=ROOT_RELS, extra=None):
    entries = {"[Content_Types].xml": CONTENT_TYPES, "_rels/.rels": root_rels, "word/document.xml": document}
    if styles is not None:
        entries["word/styles.xml"] = styles
    if document_rels is not None:
        entries["word/_rels/document.xml.rels"] = document_rels
    entries.update(extra or {})
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for name, literal in entries.items():
            archive.writestr(name, literal)
    return buffer.getvalue()


EFFECTS_REL = '''<Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2007/relationships/stylesWithEffects" Target="stylesWithEffects.xml"/>'''
CUSTOM_REL = '''<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml" Target="../customXml/item1.xml"/>'''
SETTINGS_REL = '''<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'''
CORE_REL = '''<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'''
TEMPLATE_STYLES = STYLES.replace('<w:style w:type="paragraph" w:styleId="Base">', '''
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:rsid w:val="00FC693F"/></w:style>
  <w:style w:type="paragraph" w:styleId="Base"><w:basedOn w:val="Normal"/>''')


def template_package(*, effects=TEMPLATE_STYLES):
    return docx_package(
        styles=TEMPLATE_STYLES,
        document_rels=DOCUMENT_RELS.replace("</Relationships>", EFFECTS_REL + CUSTOM_REL + "</Relationships>"),
        extra={
            "word/stylesWithEffects.xml": effects,
            "customXml/item1.xml": '<Sources xmlns="http://schemas.openxmlformats.org/officeDocument/2006/bibliography"/>',
            "customXml/_rels/item1.xml.rels": '''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXmlProps" Target="itemProps1.xml"/></Relationships>''',
            "customXml/itemProps1.xml": '<datastoreItem xmlns="http://schemas.openxmlformats.org/officeDocument/2006/customXml"/>',
        },
    )
