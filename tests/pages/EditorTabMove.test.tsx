import { useCallback, useRef, useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { Editor } from "../../src/pages/Editor";
import { EditorContext, type EditorContextType } from "../../src/contexts/EditorContext";
import { createAutoRefreshSchedule, type AutoRefreshSchedule } from "../../src/utils/autoRefresh";
import type { Tab } from "../../src/types/editor";

const mocks = vi.hoisted(() => ({
  noop: vi.fn(),
  reorderTab: vi.fn(),
  guard: vi.fn().mockResolvedValue(true),
  location: { state: null, pathname: "/editor", key: "test" },
  settings: { resultPageSize: 100, csvIncludeHeaders: true },
  capabilities: { schemas: true, sql_dialect: "postgres", identifier_quote: '"' } as Record<
    string,
    unknown
  >,
  selectedDatabases: [] as string[],
  t: (key: string) => key,
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: mocks.t }) }));
vi.mock("lucide-react", async (importOriginal) => await importOriginal());
vi.mock("react-router-dom", () => ({ useLocation: () => mocks.location, useNavigate: () => mocks.noop }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn().mockResolvedValue(() => {}), emit: vi.fn() }));
vi.mock("../../src/hooks/useDatabase", () => ({
  useDatabase: () => ({
    activeConnectionId: "connection-1",
    activeDriver: "postgres",
    activeSchema: "public",
    activeCapabilities: mocks.capabilities,
    activeDatabaseName: "testdb",
    activeConnectionName: "Test",
    connections: [],
    tables: [],
    views: [],
    materializedViews: [],
    selectedDatabases: mocks.selectedDatabases,
  }),
}));
vi.mock("../../src/hooks/useDrivers", () => ({ useDrivers: () => ({ allDrivers: [] }) }));
vi.mock("../../src/hooks/useSettings", () => ({ useSettings: () => ({ settings: mocks.settings }) }));
vi.mock("../../src/hooks/useConnectionLayoutContext", () => ({
  useConnectionLayoutContext: () => ({ explorerConnectionId: null }),
}));
vi.mock("../../src/hooks/useSavedQueries", () => ({ useSavedQueries: () => ({ saveQuery: mocks.noop }) }));
vi.mock("../../src/hooks/useQueryHistory", () => ({ useQueryHistory: () => ({ addEntry: mocks.noop }) }));
vi.mock("../../src/hooks/useKeybindings", () => ({
  useKeybindings: () => ({ matchesShortcut: mocks.noop, isMac: false }),
}));
vi.mock("../../src/hooks/useAlert", () => ({ useAlert: () => ({ showAlert: mocks.noop }) }));
vi.mock("../../src/hooks/useToast", () => ({ useToast: () => ({ showToast: mocks.noop }) }));
vi.mock("../../src/hooks/useProductionGuard", () => ({ useProductionGuard: () => mocks.guard }));
vi.mock("../../src/hooks/useQueryGuards", () => ({
  useQueryGuards: () => ({ guardQuery: mocks.guard, pending: null, resolve: mocks.noop }),
}));
vi.mock("../../src/hooks/useSqlAutocompleteRegistration", () => ({
  useSqlAutocompleteRegistration: () => {},
}));
vi.mock("../../src/components/modals/AiQueryModal", () => ({ AiQueryModal: () => null }));
vi.mock("../../src/components/modals/AiExplainModal", () => ({ AiExplainModal: () => null }));
vi.mock("../../src/components/modals/VisualExplainModal", () => ({ VisualExplainModal: () => null }));
vi.mock("../../src/components/modals/NewRowModal", () => ({ NewRowModal: () => null }));
vi.mock("../../src/components/modals/QuerySelectionModal", () => ({ QuerySelectionModal: () => null }));
vi.mock("../../src/components/modals/ConfirmModal", () => ({ ConfirmModal: () => null }));
vi.mock("../../src/components/modals/ExplainSelectionModal", () => ({ ExplainSelectionModal: () => null }));
vi.mock("../../src/components/modals/TabSwitcherModal", () => ({ TabSwitcherModal: () => null }));
vi.mock("../../src/components/modals/QueryModal", () => ({ QueryModal: () => null }));
vi.mock("../../src/components/modals/QueryParamsModal", () => ({ QueryParamsModal: () => null }));
vi.mock("../../src/components/modals/ErrorModal", () => ({ ErrorModal: () => null }));
vi.mock("../../src/components/modals/ExportProgressModal", () => ({ ExportProgressModal: () => null }));
vi.mock("../../src/components/ui/AiDropdownButton", () => ({ AiDropdownButton: () => null }));
vi.mock("../../src/components/ui/MultiResultPanel", () => ({ MultiResultPanel: () => null }));
vi.mock("../../src/components/ui/VisualQueryBuilder", () => ({ VisualQueryBuilder: () => null }));
vi.mock("../../src/components/ui/SqlEditorWrapper", () => ({ SqlEditorWrapper: () => null }));
vi.mock("../../src/components/ui/TableToolbar", () => ({ TableToolbar: () => null }));
vi.mock("../../src/components/ui/RelatedRecordsPanel", () => ({ RelatedRecordsPanel: () => null }));
vi.mock("../../src/components/ui/DataGrid", () => ({ DataGrid: () => null }));
vi.mock("../../src/components/notebook/NotebookView", () => ({ NotebookView: () => null }));
vi.mock("../../src/components/users/UserManagementView", () => ({ UserManagementView: () => null }));
vi.mock("../../src/components/layout/CommandPaletteScopeBridge", () => ({
  CommandPaletteScopeBridge: () => null,
}));

const baseTab = (overrides: Partial<Tab>): Tab => ({
  id: "tab",
  connectionId: "connection-1",
  title: "tab",
  type: "console",
  query: "",
  result: null,
  error: "",
  executionTime: null,
  page: 1,
  activeTable: null,
  pkColumns: null,
  isEditorOpen: false,
  ...overrides,
});

function Harness({ initialTabs }: { initialTabs: Tab[] }) {
  const [tabs] = useState(initialTabs);
  const [activeTabId, setActiveTabId] = useState(initialTabs[0].id);
  const schedules = useRef(new Map<string, AutoRefreshSchedule>());
  const getAutoRefreshSchedule = useCallback((id: string) => {
    let schedule = schedules.current.get(id);
    if (!schedule) {
      schedule = createAutoRefreshSchedule();
      schedules.current.set(id, schedule);
    }
    return schedule;
  }, []);
  const value = {
    tabs,
    activeTabId,
    activeTab: tabs.find((tab) => tab.id === activeTabId) ?? null,
    getAutoRefreshSchedule,
    updateTab: mocks.noop,
    setActiveTabId,
    addTab: mocks.noop,
    openNotebook: mocks.noop,
    closeTab: mocks.noop,
    closeAllTabs: mocks.noop,
    closeOtherTabs: mocks.noop,
    closeTabsToLeft: mocks.noop,
    closeTabsToRight: mocks.noop,
    reorderTab: mocks.reorderTab,
    updateResultEntry: mocks.noop,
    getSchema: mocks.noop,
    reopenClosedTab: mocks.noop,
    canReopenClosedTab: false,
  } as EditorContextType;
  return (
    <EditorContext.Provider value={value}>
      <Editor />
    </EditorContext.Provider>
  );
}

const tabs = [
  baseTab({ id: "first", title: "First" }),
  baseTab({ id: "middle", title: "Middle" }),
  baseTab({ id: "last", title: "Last" }),
];

const openTabMenu = (title: string) => {
  fireEvent.contextMenu(screen.getByRole("button", { name: title }));
  return {
    moveLeft: screen.getByRole("button", { name: "editor.moveTabLeft" }),
    moveRight: screen.getByRole("button", { name: "editor.moveTabRight" }),
  };
};

describe("Editor tab context menu move actions (#1160)", () => {
  beforeEach(() => {
    mocks.reorderTab.mockReset();
    vi.mocked(invoke).mockReset();
    vi.mocked(invoke).mockResolvedValue([]);
  });

  it("disables Move Left on the first tab and moves it one gap right", () => {
    render(<Harness initialTabs={tabs} />);
    const { moveLeft, moveRight } = openTabMenu("First");

    expect(moveLeft).toBeDisabled();
    expect(moveRight).toBeEnabled();
    fireEvent.click(moveLeft);
    expect(mocks.reorderTab).not.toHaveBeenCalled();

    fireEvent.click(moveRight);
    expect(mocks.reorderTab).toHaveBeenCalledExactlyOnceWith("first", 2);
  });

  it("disables Move Right on the last tab and moves it one gap left", () => {
    render(<Harness initialTabs={tabs} />);
    const { moveLeft, moveRight } = openTabMenu("Last");

    expect(moveRight).toBeDisabled();
    fireEvent.click(moveLeft);
    expect(mocks.reorderTab).toHaveBeenCalledExactlyOnceWith("last", 1);
  });

  it("activates a move action from the keyboard", async () => {
    const user = userEvent.setup();
    render(<Harness initialTabs={tabs} />);
    const { moveLeft } = openTabMenu("Middle");

    moveLeft.focus();
    await user.keyboard("{Enter}");
    expect(mocks.reorderTab).toHaveBeenCalledExactlyOnceWith("middle", 0);
  });
});
