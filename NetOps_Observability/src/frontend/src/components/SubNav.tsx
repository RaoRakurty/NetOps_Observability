import { NavLeaf, NavSection } from "../nav";
import { useShell } from "../context/shell";

type Props = {
  section: NavSection;
  activeLeaf?: string;
};

// Secondary horizontal nav, shown only for sections with multiple views
// (Explore, Alerts, Infrastructure, Topology, Administration). reference-grade.
export default function SubNav({ section, activeLeaf }: Props) {
  const { navigate } = useShell();
  if (!section.children) return null;
  return (
    <div className="subnav">
      {section.children.map((leaf: NavLeaf) => (
        <button
          key={leaf.id}
          className={leaf.id === activeLeaf ? "active" : ""}
          onClick={() => navigate(`${section.id}/${leaf.id}`)}
        >
          {leaf.label}
        </button>
      ))}
    </div>
  );
}
