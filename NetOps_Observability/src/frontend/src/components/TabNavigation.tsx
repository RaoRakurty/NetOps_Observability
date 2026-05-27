export type Tab = { id: string; label: string };

type Props = {
  tabs: Tab[];
  active: string;
  onSelect: (id: string) => void;
};

export default function TabNavigation({ tabs, active, onSelect }: Props) {
  return (
    <nav className="tabs">
      {tabs.map((t) => (
        <button
          key={t.id}
          className={t.id === active ? "active" : ""}
          onClick={() => onSelect(t.id)}
        >
          {t.label}
        </button>
      ))}
    </nav>
  );
}
