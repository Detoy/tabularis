import { useId } from "react";
import { useTranslation } from "react-i18next";

interface DefaultDatabaseSelectProps {
  /** The saved format uses the first selected database as the default. */
  databases: string[];
  onChange: (databases: string[]) => void;
}

export const DefaultDatabaseSelect = ({ databases, onChange }: DefaultDatabaseSelectProps) => {
  const { t } = useTranslation();
  const id = useId();
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-xs font-medium text-secondary">
        {t("newConnection.defaultDatabase")}
      </label>
      <select
        id={id}
        value={databases[0] ?? ""}
        onChange={(event) => {
          const database = event.target.value;
          if (databases.includes(database)) {
            onChange([database, ...databases.filter((db) => db !== database)]);
          }
        }}
        aria-describedby={`${id}-hint`}
        className="w-full px-2.5 py-1.5 bg-base border border-strong rounded-md text-sm text-primary focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
      >
        {databases.map((database) => (
          <option key={database} value={database}>{database}</option>
        ))}
      </select>
      <p id={`${id}-hint`} className="text-xs text-muted">
        {t("newConnection.defaultDatabaseHint")}
      </p>
    </div>
  );
};
