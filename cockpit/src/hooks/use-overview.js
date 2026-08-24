import {useCallback, useEffect, useState} from "react";
import {api} from "../api.js";
import {message} from "../lib/format.js";
import {managedServiceUnitNames, mergeSystemdState, readSystemdState} from "../systemd.js";

export function useOverview() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const overview = await api(["overview"]);
      try {
        const systemd = await readSystemdState(managedServiceUnitNames(overview));
        setData(mergeSystemdState(overview, systemd));
      } catch (_systemdError) {
        // Appliance-specific overview data remains usable if the session bus
        // cannot provide live systemd state (for example during early boot).
        setData(overview);
      }
      setError("");
    } catch (reason) {
      setError(message(reason));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return {data, loading, error, refresh, setData};
}
