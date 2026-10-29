import os
import zipfile
import shutil
from typing import List, Tuple, Set, Optional

# File limits for safe local processing
MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB per single file
MAX_TOTAL_UNCOMPRESSED_SIZE = 500 * 1024 * 1024  # 500 MB total uncompressed
MAX_TOTAL_FILES = 50000  # Up to 50,000 files

# Standard directories to skip during scanning
IGNORE_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "__pycache__",
    ".pytest_cache", ".venv", "venv", "env", ".idea", ".vscode",
    "dist", "build", ".mypy_cache", ".tox", "target", "bin", "obj"
}

# File extensions that are typically binary and should be skipped
BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".img",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".pyd", ".class", ".jar", ".war",
    ".db", ".sqlite", ".sqlite3", ".parquet"
}

# Recognized text and source-code file extensions
SUPPORTED_SOURCE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".cc", ".h",
    ".hpp", ".cs", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".kts",
    ".scala", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env", ".tf", ".tfvars", ".sql", ".txt", ".md", ".rst",
    ".html", ".htm", ".css", ".scss", ".dockerfile", "dockerfile", "jenkinsfile"
}


def is_binary_file(filepath: str) -> bool:
    """
    Check if a file is binary using extension check and null-byte inspection.
    """
    _, ext = os.path.splitext(filepath)
    if ext.lower() in BINARY_EXTENSIONS:
        return True

    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            if b"\0" in chunk:
                return True
    except Exception:
        return True

    return False


def is_scannable_file(filepath: str) -> bool:
    """
    Determines if a file is suitable for secret scanning.
    """
    filename = os.path.basename(filepath).lower()

    # Special filenames without standard extensions
    special_names = {"dockerfile", "containerfile", "jenkinsfile", "makefile", ".env"}
    if filename in special_names or filename.startswith(".env."):
        return True

    _, ext = os.path.splitext(filename)
    if ext in BINARY_EXTENSIONS:
        return False

    return True


def should_skip_zip_member(member_name: str) -> bool:
    """
    Checks if a zip member resides inside an ignored directory.
    """
    norm = member_name.replace("\\", "/").strip("/")
    parts = [p for p in norm.split("/") if p and p != "."]
    for p in parts[:-1]:
        if p in IGNORE_DIRS:
            return True
        if p.startswith(".") and p not in [".github", ".gitlab", ".circleci"]:
            return True
    return False


def safe_extract_zip(zip_path: str, target_dir: str) -> Tuple[bool, str, int]:
    """
    Safely extract a ZIP archive while preventing Zip-Slip (path traversal)
    and ZIP Bomb denial-of-service attacks.
    """
    if not os.path.isfile(zip_path):
        return False, f"ZIP file not found at: {zip_path}", 0

    if not zipfile.is_zipfile(zip_path):
        return False, "Invalid ZIP archive file format.", 0

    os.makedirs(target_dir, exist_ok=True)
    target_dir_abs = os.path.abspath(target_dir)

    total_size = 0
    total_files = 0

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()

            # Pre-extraction security check: validate ALL members for Zip Slip path traversal
            for member in infolist:
                norm_fn = member.filename.replace("\\", "/").strip("/")
                parts = norm_fn.split("/")
                if ".." in parts:
                    return False, f"Security Exception: Path traversal attempt detected in '{member.filename}'.", 0

                extracted_path = os.path.abspath(os.path.join(target_dir_abs, member.filename))
                if not extracted_path.startswith(target_dir_abs + os.sep) and extracted_path != target_dir_abs:
                    return False, f"Security Exception: Path traversal attempt detected in '{member.filename}'.", 0

            file_members = [
                m for m in infolist
                if not m.is_dir() and not should_skip_zip_member(m.filename)
            ]

            if len(file_members) > MAX_TOTAL_FILES:
                return False, f"ZIP archive exceeds maximum file count limit ({MAX_TOTAL_FILES}).", 0

            # Validate against Zip Bomb limits
            for member in file_members:
                total_size += member.file_size
                if total_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
                    return False, f"Security Exception: Uncompressed ZIP size exceeds maximum limit ({MAX_TOTAL_UNCOMPRESSED_SIZE // (1024*1024)} MB).", 0

            # Second pass: safely extract files
            for member in file_members:
                extracted_path = os.path.abspath(os.path.join(target_dir_abs, member.filename))
                os.makedirs(os.path.dirname(extracted_path), exist_ok=True)
                with zf.open(member) as source, open(extracted_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                total_files += 1

        return True, "Success", total_files

    except Exception as e:
        return False, f"Failed to extract ZIP archive: {str(e)}", 0


def collect_files_to_scan(base_dir: str) -> List[Tuple[str, str]]:
    """
    Recursively collects all readable, non-binary text files in base_dir.
    Returns list of tuples: (relative_path, absolute_path).
    """
    base_dir_abs = os.path.abspath(base_dir)
    collected = []

    allowed_dot_dirs = {".github", ".gitlab", ".circleci"}
    for root, dirs, files in os.walk(base_dir_abs):
        # Prune ignored directories in-place while keeping allowed dot directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and (not d.startswith(".") or d in allowed_dot_dirs)]

        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir_abs).replace("\\", "/")

            if not is_scannable_file(full_path) or is_binary_file(full_path):
                continue

            try:
                if os.path.getsize(full_path) > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            collected.append((rel_path, full_path))

    return collected


def read_file_safe(file_path: str) -> Optional[str]:
    """
    Safely reads file content with utf-8 decoding, falling back gracefully.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        try:
            with open(file_path, "r", encoding="latin-1", errors="ignore") as f:
                return f.read()
        except Exception:
            return None
