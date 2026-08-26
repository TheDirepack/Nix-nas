import React from 'react';
import { FormGroup, FormSelect, FormSelectOption, HelperText, HelperTextItem } from '@patternfly/react-core';

const LANGUAGES = [
  ['en', 'English'],
  ['de', 'Deutsch'],
  ['es', 'Español'],
  ['fr', 'Français'],
  ['it', 'Italiano'],
  ['ja', '日本語'],
  ['nl', 'Nederlands'],
  ['pt-BR', 'Português (Brasil)'],
  ['zh-CN', '简体中文'],
];

const FALLBACK_TIMEZONES = [
  'UTC',
  'America/Los_Angeles',
  'America/Chicago',
  'America/New_York',
  'America/Sao_Paulo',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Paris',
  'Asia/Kolkata',
  'Asia/Shanghai',
  'Asia/Tokyo',
  'Australia/Sydney',
];

const TIMEZONES = (() => {
  const supported = typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : [];
  return ['UTC', ...(supported.length ? supported : FALLBACK_TIMEZONES.filter((value) => value !== 'UTC'))];
})();

const LanguageStep = ({ language, onLanguage, timezone, onTimezone }) => (
  <div className="nas-wizard-step">
    <p className="nas-wizard-intro">
      Choose the language and time zone used by the appliance for dates, schedules, logs, and
      operator messages. You can change these values later from the appliance settings.
    </p>
    <FormGroup label="Language" fieldId="wizard-language-input" isRequired>
      <FormSelect
        id="wizard-language-input"
        value={language}
        onChange={(_event, value) => onLanguage(value)}
      >
        {LANGUAGES.map(([value, label]) => (
          <FormSelectOption key={value} value={value} label={label} />
        ))}
      </FormSelect>
      <HelperText>
        <HelperTextItem>Used for the setup summary and future localized appliance messages.</HelperTextItem>
      </HelperText>
    </FormGroup>
    <FormGroup label="Timezone" fieldId="wizard-timezone-input" isRequired>
      <FormSelect
        id="wizard-timezone-input"
        value={timezone}
        onChange={(_event, value) => onTimezone(value)}
      >
        {TIMEZONES.map((value) => (
          <FormSelectOption key={value} value={value} label={value} />
        ))}
      </FormSelect>
      <HelperText>
        <HelperTextItem>Pick the IANA time zone for schedules and timestamps, for example America/New_York.</HelperTextItem>
      </HelperText>
    </FormGroup>
  </div>
);

export default LanguageStep;
