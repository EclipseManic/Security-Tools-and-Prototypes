import { create } from "zustand";

interface ScanStore {
  activeScans: Set<number>;
  setActiveScan: (id: number, active: boolean) => void;
}

export const useScanStore = create<ScanStore>((set) => ({
  activeScans: new Set(),
  setActiveScan: (id, active) =>
    set((state) => {
      const newSet = new Set(state.activeScans);
      if (active) newSet.add(id);
      else newSet.delete(id);
      return { activeScans: newSet };
    }),
}));
