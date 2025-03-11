from pathlib import Path
import os
import sys
from dotenv import load_dotenv, find_dotenv

"""
Generic Backend

Silvio Weging 2024

Contains: Django settings for code_General project.

"""

import os

from main.settings.base import TEMPLATES, BASE_DIR

###############################################################
TEMPLATE_DIR = os.path.join(BASE_DIR, "code_General", "templates")
TEMPLATES[0]["DIRS"].append(TEMPLATE_DIR)