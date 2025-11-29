"""
ASCII world map widget for visualizing attack origins geographically.

Displays a simplified world map with markers for attack source locations.
"""

from collections import defaultdict
from typing import Dict, List, Tuple

from rich.console import RenderableType
from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static

from ...core.models import Statistics


# Simplified ASCII world map (40x20 characters)
WORLD_MAP = """
                    ..
     ......        .....
    ........      .......
   ........ ................
  ..................  ......    .....
 .................... ........  ......
....................  ........  .......
...................    .......  .......
 .................      ......  .......
  ...............        .....  .......
   .....   .....          ....   .....
            ....            ...    ....
             ...             ..     ...
              ..                     ...
                                      ..
"""

# Approximate coordinate mapping for major regions
# Format: (country_code, (row, col))
COUNTRY_POSITIONS = {
    "US": (7, 8),
    "CA": (5, 10),
    "MX": (9, 9),
    "BR": (12, 18),
    "GB": (5, 21),
    "FR": (6, 22),
    "DE": (5, 23),
    "ES": (7, 21),
    "IT": (6, 24),
    "RU": (4, 30),
    "CN": (6, 35),
    "JP": (6, 39),
    "IN": (9, 32),
    "AU": (13, 37),
    "ZA": (13, 25),
    "EG": (8, 26),
    "NG": (9, 23),
    "KR": (6, 37),
    "PL": (5, 25),
    "TR": (7, 27),
    "SA": (9, 28),
    "ID": (11, 35),
    "TH": (10, 34),
    "VN": (10, 35),
    "PH": (10, 37),
    "MY": (11, 34),
    "SG": (11, 35),
    "AR": (13, 17),
    "CL": (13, 16),
    "CO": (10, 16),
    "PE": (11, 16),
    "VE": (10, 17),
    "UA": (6, 27),
    "SE": (4, 24),
    "NO": (3, 23),
    "FI": (3, 26),
    "DK": (4, 23),
    "NL": (5, 22),
    "BE": (5, 22),
    "CH": (6, 23),
    "AT": (6, 24),
    "CZ": (5, 24),
    "GR": (7, 25),
    "RO": (6, 26),
    "BG": (7, 26),
    "RS": (6, 25),
    "HR": (6, 24),
    "HU": (6, 25),
    "SK": (5, 25),
    "SI": (6, 24),
    "IL": (8, 27),
    "JO": (8, 27),
    "IQ": (8, 28),
    "IR": (8, 29),
    "AE": (9, 29),
    "KW": (8, 28),
    "QA": (9, 29),
    "PK": (8, 31),
    "BD": (9, 33),
    "LK": (10, 32),
    "NP": (8, 32),
    "MM": (10, 33),
    "LA": (10, 34),
    "KH": (10, 35),
    "NZ": (14, 40),
}


class WorldMap(Static):
    """
    ASCII world map widget showing attack geographic distribution.
    """

    stats: reactive[Statistics | None] = reactive(None)

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize world map widget."""
        super().__init__(name=name, id=id, classes=classes)
        self._attack_counts: Dict[str, int] = defaultdict(int)

    def watch_stats(self, stats: Statistics | None) -> None:
        """Update map when stats change."""
        if stats:
            # Update attack counts from top countries
            self._attack_counts.clear()
            for country, count in stats.top_countries:
                self._attack_counts[country] = count

            self.update(self._render_map())

    def _render_map(self) -> RenderableType:
        """Render the world map with attack markers."""
        # Parse base map into list of lists
        lines = WORLD_MAP.strip().split('\n')
        map_grid = [list(line.ljust(45)) for line in lines]  # Ensure consistent width

        # Place attack markers
        for country, count in self._attack_counts.items():
            if country in COUNTRY_POSITIONS:
                row, col = COUNTRY_POSITIONS[country]

                # Ensure coordinates are within bounds
                if 0 <= row < len(map_grid) and 0 <= col < len(map_grid[row]):
                    # Determine marker based on count
                    if count > 100:
                        marker = '█'  # Heavy activity
                    elif count > 50:
                        marker = '▓'  # Medium activity
                    elif count > 10:
                        marker = '▒'  # Light activity
                    else:
                        marker = '░'  # Minimal activity

                    map_grid[row][col] = marker

        # Create rich text with colors
        text = Text()
        text.append("Attack Origin Map\n", style="bold cyan")
        text.append("─" * 45 + "\n", style="dim")

        for row in map_grid:
            line = ''.join(row)
            # Color the map
            for char in line:
                if char == '█':
                    text.append(char, style="red bold")
                elif char == '▓':
                    text.append(char, style="yellow")
                elif char == '▒':
                    text.append(char, style="green")
                elif char == '░':
                    text.append(char, style="cyan")
                elif char == '.':
                    text.append(char, style="blue dim")
                else:
                    text.append(char, style="dim")
            text.append("\n")

        # Add legend
        text.append("\n" + "─" * 45 + "\n", style="dim")
        text.append("Legend: ", style="dim")
        text.append("█ ", style="red bold")
        text.append("Heavy (>100)  ", style="dim")
        text.append("▓ ", style="yellow")
        text.append("Medium (50-100)  ", style="dim")
        text.append("▒ ", style="green")
        text.append("Light (10-50)  ", style="dim")
        text.append("░ ", style="cyan")
        text.append("Min (<10)", style="dim")

        return text
