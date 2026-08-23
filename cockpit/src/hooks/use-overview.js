import {useCallback, useEffect, useState} from "react";
import {api} from "../api.js";
import {message} from "../lib/format.js";

export function useOverview() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api(["overview"]));
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
