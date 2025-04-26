#!/usr/bin/env python3
# Author: Aaron Lesmeister (enhancements by Claude)
# Date: 2025.04.08
# Convert PDF, DOCX, or website content to markdown format for Obsidian or RAG systems.
# This script uses PyMuPDF for PDF processing and python-docx for DOCX processing.
#
# Example: document2md.py https://attack.mitre.org/techniques/T1190/ --output ./rag_data
#
import os
import sys
import argparse
import fitz  # PyMuPDF
import docx
import requests
from bs4 import BeautifulSoup
import re
import hashlib
from urllib.parse import urlparse
from datetime import datetime

def convert_pdf_to_markdown(pdf_path, output_dir=None):
    """Convert PDF to markdown with proper formatting."""
    try:
        # Open the PDF
        doc = fitz.open(pdf_path)
        
        # Extract filename for the output
        pdf_filename = os.path.basename(pdf_path)
        base_filename = os.path.splitext(pdf_filename)[0]
        
        # Determine output path
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"{base_filename}.md")
        else:
            output_path = f"{base_filename}.md"
        
        # Extract text with formatting
        content = []
        metadata = {}
        
        # Extract metadata if available
        metadata["title"] = doc.metadata.get("title", base_filename)
        metadata["author"] = doc.metadata.get("author", "Unknown")
        metadata["creation_date"] = doc.metadata.get("creationDate", "Unknown")
        
        # Process each page
        for page_num, page in enumerate(doc):
            # Extract text with formatting information
            blocks = page.get_text("dict")["blocks"]
            
            for block in blocks:
                if "lines" in block:
                    for line in block["lines"]:
                        for span in line["spans"]:
                            text = span["text"]
                            font_size = span["size"]
                            font_name = span["font"]
                            
                            # Attempt to determine if this is a heading based on font size
                            if font_size > 12:  # Assuming larger fonts are headings
                                heading_level = min(int((font_size - 12) / 2) + 1, 6)
                                content.append(f"{'#' * heading_level} {text}")
                            else:
                                content.append(text)
                        
                        # Add a newline after each line
                        content.append("\n")
                    
                    # Add an extra newline between blocks for paragraphs
                    content.append("\n")
        
        # Create markdown content with frontmatter
        markdown_content = f"""---
title: "{metadata['title']}"
author: "{metadata['author']}"
date: "{metadata['creation_date']}"
source: "Converted from PDF"
---

"""
        markdown_content += "\n".join(content)
        
        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
            
        print(f"Successfully converted {pdf_path} to {output_path}")
        return output_path
        
    except Exception as e:
        print(f"Error converting PDF {pdf_path}: {str(e)}")
        return None

def convert_docx_to_markdown(docx_path, output_dir=None):
    """Convert DOCX to markdown with proper formatting."""
    try:
        # Open the document
        doc = docx.Document(docx_path)
        
        # Extract filename for the output
        docx_filename = os.path.basename(docx_path)
        base_filename = os.path.splitext(docx_filename)[0]
        
        # Determine output path
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"{base_filename}.md")
        else:
            output_path = f"{base_filename}.md"
        
        # Extract document properties if available
        title = base_filename
        author = "Unknown"
        
        try:
            core_properties = doc.core_properties
            if core_properties.title:
                title = core_properties.title
            if core_properties.author:
                author = core_properties.author
            creation_date = core_properties.created or datetime.now()
        except:
            creation_date = datetime.now()
        
        # Create markdown content with frontmatter
        markdown_content = f"""---
title: "{title}"
author: "{author}"
date: "{creation_date.strftime('%Y-%m-%d')}"
source: "Converted from DOCX"
---

"""
        
        # Process each paragraph
        for para in doc.paragraphs:
            # Skip empty paragraphs
            if not para.text.strip():
                markdown_content += "\n\n"
                continue
            
            # Check for heading style
            if para.style.name.startswith('Heading'):
                heading_level = int(para.style.name.replace('Heading', ''))
                markdown_content += f"{'#' * heading_level} {para.text}\n\n"
            else:
                # Process runs to handle bold, italic, etc.
                para_text = ""
                for run in para.runs:
                    text = run.text
                    if run.bold and run.italic:
                        text = f"***{text}***"
                    elif run.bold:
                        text = f"**{text}**"
                    elif run.italic:
                        text = f"*{text}*"
                    para_text += text
                
                markdown_content += f"{para_text}\n\n"
        
        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
            
        print(f"Successfully converted {docx_path} to {output_path}")
        return output_path
        
    except Exception as e:
        print(f"Error converting DOCX {docx_path}: {str(e)}")
        return None

def convert_website_to_markdown(url, output_dir=None):
    """Convert website content to markdown."""
    try:
        # Parse URL to create a filename
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path.strip("/").replace("/", "_")
        
        if not path:
            path = "index"
            
        # Create a unique filename based on the URL
        base_filename = f"{domain}_{path}"
        # Hash longer filenames to avoid path length issues
        if len(base_filename) > 50:
            url_hash = hashlib.md5(url.encode()).hexdigest()[:10]
            base_filename = f"{domain}_{url_hash}"
        
        # Determine output path
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"{base_filename}.md")
        else:
            output_path = f"{base_filename}.md"
        
        # Fetch the website content
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        # Parse the HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract title
        title = soup.title.string if soup.title else domain
        
        # Remove unwanted elements (adjust as needed)
        for element in soup.select('script, style, nav, footer, header, .ads, .comments, aside'):
            element.decompose()
        
        # Create markdown content with frontmatter
        markdown_content = f"""---
title: "{title}"
source_url: "{url}"
date: "{datetime.now().strftime('%Y-%m-%d')}"
---

# {title}

"""
        
        # Extract main content (adjust selectors based on website structure)
        main_content = soup.select_one('main, article, .content, #content, .post, .article')
        
        if not main_content:
            # Fallback to body if no specific content container found
            main_content = soup.body
        
        # Process headings
        for i in range(1, 7):
            for heading in main_content.find_all(f'h{i}'):
                text = heading.get_text().strip()
                heading.replace_with(f"{'#' * (i+1)} {text}\n\n")
        
        # Process paragraphs
        for para in main_content.find_all('p'):
            text = para.get_text().strip()
            para.replace_with(f"{text}\n\n")
        
        # Process lists
        for ul in main_content.find_all('ul'):
            list_items = ""
            for li in ul.find_all('li'):
                text = li.get_text().strip()
                list_items += f"- {text}\n"
            ul.replace_with(list_items + "\n")
        
        for ol in main_content.find_all('ol'):
            list_items = ""
            for i, li in enumerate(ol.find_all('li')):
                text = li.get_text().strip()
                list_items += f"{i+1}. {text}\n"
            ol.replace_with(list_items + "\n")
        
        # Get cleaned text
        content = main_content.get_text()
        
        # Clean up whitespace
        content = re.sub(r'\n{3,}', '\n\n', content)
        
        markdown_content += content
        
        # Add source reference at the end
        markdown_content += f"\n\n---\nSource: [{url}]({url})\n"
        
        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
            
        print(f"Successfully converted {url} to {output_path}")
        return output_path
        
    except Exception as e:
        print(f"Error converting website {url}: {str(e)}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Convert documents to markdown for Obsidian or RAG systems")
    parser.add_argument("source", help="PDF file, DOCX file, or website URL to convert")
    parser.add_argument("--output", "-o", help="Output directory for markdown files")
    
    args = parser.parse_args()
    
    # Determine the input type and process accordingly
    if args.source.lower().endswith('.pdf'):
        if not os.path.exists(args.source):
            print(f"Error: PDF file '{args.source}' not found")
            return
        convert_pdf_to_markdown(args.source, args.output)
    
    elif args.source.lower().endswith('.docx'):
        if not os.path.exists(args.source):
            print(f"Error: DOCX file '{args.source}' not found")
            return
        convert_docx_to_markdown(args.source, args.output)
    
    elif args.source.lower().startswith(('http://', 'https://')):
        convert_website_to_markdown(args.source, args.output)
    
    else:
        print("Error: Unsupported file format. Please provide a PDF, DOCX, or website URL.")

if __name__ == "__main__":
    main()