#!/bin/bash
echo "[+] Creating Keres..."
cd ~/keres

# __init__.py
cat > keres/__init__.py << 'EOF'
"""Keres - autonomous bug bounty hunting engine."""
__version__ = "1.0.0"
EOF

# __main__.py
cat > keres/__main__.py << 'EOF'
from .cli import main
if __name__ == "__main__":
    main()
EOF

# modules/__init__.py
cat > keres/modules/__init__.py << 'EOF'
"""Keres operational modules."""
EOF

# utils/__init__.py
cat > keres/utils/__init__.py << 'EOF'
"""Keres utility modules."""
EOF

echo "[+] Core files created."
echo "[+] Now paste the remaining files one by one."
