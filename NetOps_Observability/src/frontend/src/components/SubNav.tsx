import { NavLeaf, NavSection } from "../nav";
import { useShell } from "../context/shell";

type Props = {
  section: NavSection;
  activeLeaf?: string;
};

// Secondary horizontal nav, shown only for sections with multiple views
// (Explore, Alerts, Infrastructure, Topology, Administration). When a section's
// leaves declare `group`, the bar renders a two-layer hierarchy: a small
// uppercase group label introduces each run of grouped leaves (mirrors the
// rail flyout's group headers) so a wide section like Infrastructure doesn't
// read as one flat tab row.
export default function SubNav({ section, activeLeaf }: Props) {
  const { navigate } = useShell();
  if (!section.children) return null;
  let lastGroup: string | undefined;
  return (
    <nav className="subnav" aria-label={`${section.label} views`}>
      {section.children.map((leaf: NavLeaf) => {
        const header = leaf.group && leaf.group !== lastGroup ? leaf.group : null;
        lastGroup = leaf.group;
        return (
          <span key={leaf.id} className="subnav-cell">
            {header && <span className="subnav-group">{header}</span>}
            <button
              className={leaf.id === activeLeaf ? "active" : ""}
              aria-current={leaf.id === activeLeaf ? "page" : undefined}
              onClick={() => navigate(`${section.id}/${leaf.id}`)}
            >
              {leaf.label}
            </button>
          </span>
        );
      })}
    </nav>
  );
}
