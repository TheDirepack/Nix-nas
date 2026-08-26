import React from 'react';
import { Alert, Progress } from '@patternfly/react-core';
import { passwordQuality } from './api.js';

export const usePasswordQualityCheck = (userInputs = []) => {
  const [quality, setQuality] = React.useState(null);
  const [error, setError] = React.useState('');

  const check = React.useCallback(async (password) => {
    if (!password) {
      setQuality(null);
      setError('');
      return;
    }
    try {
      setError('');
      setQuality(await passwordQuality(password, userInputs.filter(Boolean)));
    } catch (reason) {
      setQuality(null);
      setError(String(reason));
    }
  }, [userInputs]);

  return { quality, error, check };
};

export const PasswordQualityFeedback = ({ label, quality, error }) => {
  if (error) {
    return <Alert isInline variant="warning" title={`${label} strength check unavailable`}>{error}</Alert>;
  }
  if (!quality) return null;
  const score = Number.isInteger(quality.zxcvbnScore) ? quality.zxcvbnScore : 0;
  const detail = [quality.warning, ...(quality.suggestions || [])].filter(Boolean).join(' ');
  let variant = 'success';
  if (quality.breachStatus === 'breached' || !quality.localAccepted) variant = 'danger';
  else if (quality.breachStatus === 'unavailable') variant = 'warning';
  return (
    <Alert isInline variant={variant} title={`${label} strength: ${score}/4`}>
      <Progress value={score * 25} aria-label={`${label} password strength`} />
      {quality.breachStatus === 'breached' && <p>This password is known to be breached and cannot be used.</p>}
      {quality.breachStatus === 'unavailable' && <p>The online breach check is unavailable; local strength rules still apply.</p>}
      {detail && <p>{detail}</p>}
    </Alert>
  );
};
