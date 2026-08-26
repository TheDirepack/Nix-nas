import React from 'react';
import {
  Button,
  FormGroup,
  HelperText,
  HelperTextItem,
  MenuToggle,
  Select,
  SelectList,
  SelectOption,
  TextInputGroup,
  TextInputGroupMain,
  TextInputGroupUtilities,
} from '@patternfly/react-core';

const LANGUAGES = [
  ['en', 'English'],
  ['de', 'Deutsch'],
  ['es', 'Español'],
  ['fr', 'Français'],
  ['it', 'Italiano'],
  ['ja', '日本語'],
  ['ko', '한국어'],
  ['nl', 'Nederlands'],
  ['pl', 'Polski'],
  ['pt-BR', 'Português (Brasil)'],
  ['pt-PT', 'Português (Portugal)'],
  ['ru', 'Русский'],
  ['sv', 'Svenska'],
  ['tr', 'Türkçe'],
  ['zh-CN', '简体中文'],
  ['zh-TW', '繁體中文'],
];

const KEY_TIMEZONES = [
  ['UTC', 'UTC', 'Coordinated Universal Time'],
  ['America/Anchorage', 'Anchorage', 'Alaska'],
  ['America/Los_Angeles', 'Los Angeles', 'Pacific Time'],
  ['America/Denver', 'Denver', 'Mountain Time'],
  ['America/Chicago', 'Chicago', 'Central Time'],
  ['America/New_York', 'New York', 'Eastern Time'],
  ['America/Toronto', 'Toronto', 'Eastern Canada'],
  ['America/Halifax', 'Halifax', 'Atlantic Canada'],
  ['America/St_Johns', "St. John's", 'Newfoundland'],
  ['America/Phoenix', 'Phoenix', 'Arizona'],
  ['America/Mexico_City', 'Mexico City', 'Central Mexico'],
  ['America/Vancouver', 'Vancouver', 'Pacific Canada'],
  ['America/Winnipeg', 'Winnipeg', 'Central Canada'],
  ['America/Edmonton', 'Edmonton', 'Mountain Canada'],
  ['America/Bogota', 'Bogotá', 'Colombia'],
  ['America/Lima', 'Lima', 'Peru'],
  ['America/Santiago', 'Santiago', 'Chile'],
  ['America/Sao_Paulo', 'São Paulo', 'Brazil'],
  ['America/Argentina/Buenos_Aires', 'Buenos Aires', 'Argentina'],
  ['America/Montevideo', 'Montevideo', 'Uruguay'],
  ['America/Caracas', 'Caracas', 'Venezuela'],
  ['Pacific/Honolulu', 'Honolulu', 'Hawaii'],
  ['Atlantic/Reykjavik', 'Reykjavík', 'Iceland'],
  ['Europe/London', 'London', 'United Kingdom'],
  ['Europe/Dublin', 'Dublin', 'Ireland'],
  ['Europe/Lisbon', 'Lisbon', 'Portugal'],
  ['Europe/Paris', 'Paris', 'France'],
  ['Europe/Madrid', 'Madrid', 'Spain'],
  ['Europe/Berlin', 'Berlin', 'Germany'],
  ['Europe/Rome', 'Rome', 'Italy'],
  ['Europe/Amsterdam', 'Amsterdam', 'Netherlands'],
  ['Europe/Brussels', 'Brussels', 'Belgium'],
  ['Europe/Zurich', 'Zurich', 'Switzerland'],
  ['Europe/Stockholm', 'Stockholm', 'Sweden'],
  ['Europe/Warsaw', 'Warsaw', 'Poland'],
  ['Europe/Prague', 'Prague', 'Czechia'],
  ['Europe/Athens', 'Athens', 'Greece'],
  ['Europe/Helsinki', 'Helsinki', 'Finland'],
  ['Europe/Bucharest', 'Bucharest', 'Romania'],
  ['Europe/Kyiv', 'Kyiv', 'Ukraine'],
  ['Europe/Istanbul', 'Istanbul', 'Türkiye'],
  ['Europe/Moscow', 'Moscow', 'Russia'],
  ['Africa/Casablanca', 'Casablanca', 'Morocco'],
  ['Africa/Cairo', 'Cairo', 'Egypt'],
  ['Africa/Lagos', 'Lagos', 'Nigeria'],
  ['Africa/Nairobi', 'Nairobi', 'Kenya'],
  ['Africa/Johannesburg', 'Johannesburg', 'South Africa'],
  ['Asia/Jerusalem', 'Jerusalem', 'Israel'],
  ['Asia/Dubai', 'Dubai', 'United Arab Emirates'],
  ['Asia/Riyadh', 'Riyadh', 'Saudi Arabia'],
  ['Asia/Tehran', 'Tehran', 'Iran'],
  ['Asia/Karachi', 'Karachi', 'Pakistan'],
  ['Asia/Kolkata', 'Kolkata', 'India'],
  ['Asia/Dhaka', 'Dhaka', 'Bangladesh'],
  ['Asia/Almaty', 'Almaty', 'Kazakhstan'],
  ['Asia/Bangkok', 'Bangkok', 'Thailand'],
  ['Asia/Ho_Chi_Minh', 'Ho Chi Minh City', 'Vietnam'],
  ['Asia/Singapore', 'Singapore', 'Singapore'],
  ['Asia/Jakarta', 'Jakarta', 'Indonesia'],
  ['Asia/Shanghai', 'Shanghai', 'China'],
  ['Asia/Hong_Kong', 'Hong Kong', 'Hong Kong'],
  ['Asia/Taipei', 'Taipei', 'Taiwan'],
  ['Asia/Tokyo', 'Tokyo', 'Japan'],
  ['Asia/Seoul', 'Seoul', 'South Korea'],
  ['Asia/Manila', 'Manila', 'Philippines'],
  ['Australia/Perth', 'Perth', 'Western Australia'],
  ['Australia/Adelaide', 'Adelaide', 'South Australia'],
  ['Australia/Darwin', 'Darwin', 'Northern Territory'],
  ['Australia/Brisbane', 'Brisbane', 'Queensland'],
  ['Australia/Sydney', 'Sydney', 'New South Wales'],
  ['Pacific/Auckland', 'Auckland', 'New Zealand'],
  ['Pacific/Fiji', 'Fiji', 'Fiji'],
  ['Pacific/Guam', 'Guam', 'Guam'],
];

const toSearchOption = ([value, label, description]) => ({
  value,
  label,
  description,
  search: `${value} ${label} ${description}`.toLocaleLowerCase(),
});

const languageOptions = LANGUAGES.map(([value, label]) => toSearchOption([value, label, value]));
const supportedTimezones = new Set(
  typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : [],
);

const formatOffset = (value) => {
  try {
    const part = new Intl.DateTimeFormat('en', { timeZone: value, timeZoneName: 'shortOffset' })
      .formatToParts(new Date())
      .find((item) => item.type === 'timeZoneName')?.value;
    return part && part !== 'GMT' ? part.replace(/^GMT/, 'UTC') : 'UTC';
  } catch (_error) {
    return '';
  }
};

const timezoneOptions = KEY_TIMEZONES
  .filter(([value]) => value === 'UTC' || !supportedTimezones.size || supportedTimezones.has(value))
  .map(([value, label, region]) => {
    const offset = formatOffset(value);
    const description = [region, offset].filter(Boolean).join(' · ');
    return toSearchOption([value, label, description]);
  });

const browserTimezone = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch (_error) {
    return 'UTC';
  }
})();

if (!timezoneOptions.some((option) => option.value === browserTimezone) && browserTimezone !== 'UTC') {
  timezoneOptions.unshift(toSearchOption([browserTimezone, 'Current browser time zone', browserTimezone]));
}

export const DEFAULT_LANGUAGE = (() => {
  const browserLanguage = typeof navigator !== 'undefined' ? navigator.language : '';
  return languageOptions.some((option) => option.value === browserLanguage)
    ? browserLanguage
    : languageOptions.find((option) => option.value === browserLanguage.split('-')[0])?.value || 'en';
})();

export const DEFAULT_TIMEZONE = timezoneOptions.some((option) => option.value === browserTimezone)
  ? browserTimezone
  : 'UTC';

const SearchableSelect = ({ id, value, onChange, options, placeholder }) => {
  const [isOpen, setIsOpen] = React.useState(false);
  const [query, setQuery] = React.useState('');
  const inputRef = React.useRef(null);
  const selected = options.find((option) => option.value === value);
  const inputValue = query || selected?.label || '';
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const filtered = normalizedQuery
    ? options.filter((option) => option.search.includes(normalizedQuery))
    : options;

  const selectOption = (selectedValue) => {
    onChange(selectedValue);
    setQuery('');
    setIsOpen(false);
  };

  const toggle = (toggleRef) => (
    <MenuToggle
      ref={toggleRef}
      variant="typeahead"
      isExpanded={isOpen}
      isFullWidth
      aria-label={placeholder}
      onClick={() => {
        setIsOpen((open) => !open);
        inputRef.current?.focus();
      }}
    >
      <TextInputGroup isPlain>
        <TextInputGroupMain
          id={id}
          innerRef={inputRef}
          value={inputValue}
          placeholder={placeholder}
          autoComplete="off"
          role="combobox"
          aria-expanded={isOpen}
          aria-controls={`${id}-listbox`}
          onFocus={(event) => {
            event.currentTarget.select();
            if (!isOpen) setIsOpen(true);
          }}
          onChange={(_event, nextValue) => {
            setQuery(nextValue);
            setIsOpen(true);
          }}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && filtered.length === 1) {
              event.preventDefault();
              selectOption(filtered[0].value);
            }
            if (event.key === 'Escape') {
              setQuery('');
              setIsOpen(false);
            }
          }}
        />
        {query && (
          <TextInputGroupUtilities>
            <Button
              variant="plain"
              type="button"
              aria-label={`Clear ${placeholder}`}
              onClick={(event) => {
                event.stopPropagation();
                setQuery('');
                inputRef.current?.focus();
              }}
            >
              ×
            </Button>
          </TextInputGroupUtilities>
        )}
      </TextInputGroup>
    </MenuToggle>
  );

  return (
    <Select
      id={`${id}-select`}
      isOpen={isOpen}
      selected={value}
      variant="typeahead"
      toggle={toggle}
      onSelect={(_event, selectedValue) => selectOption(String(selectedValue))}
      onOpenChange={(open) => {
        setIsOpen(open);
        if (!open) setQuery('');
      }}
      maxMenuHeight="18rem"
    >
      <SelectList id={`${id}-listbox`}>
        {filtered.length ? (
          filtered.map((option) => (
            <SelectOption key={option.value} value={option.value} description={option.description}>
              {option.label}
            </SelectOption>
          ))
        ) : (
          <SelectOption value="__no-results__" isDisabled>
            No matches found
          </SelectOption>
        )}
      </SelectList>
    </Select>
  );
};

const LanguageStep = ({ language, onLanguage, timezone, onTimezone }) => (
  <div className="nas-wizard-step">
    <p className="nas-wizard-intro">
      Choose the language and time zone used by the appliance. Search by a language, city, region,
      or IANA zone name; the list keeps only familiar cities while preserving the exact system zone.
    </p>
    <FormGroup label="Language" fieldId="wizard-language-input" isRequired>
      <SearchableSelect
        id="wizard-language-input"
        value={language}
        onChange={onLanguage}
        options={languageOptions}
        placeholder="Search languages"
      />
      <HelperText>
        <HelperTextItem>Used for the setup summary and future localized appliance messages.</HelperTextItem>
      </HelperText>
    </FormGroup>
    <FormGroup label="Timezone" fieldId="wizard-timezone-input" isRequired>
      <SearchableSelect
        id="wizard-timezone-input"
        value={timezone}
        onChange={onTimezone}
        options={timezoneOptions}
        placeholder="Search cities or regions"
      />
      <HelperText>
        <HelperTextItem>
          The saved value is an IANA zone such as America/New_York. The offset shown in each result reflects the current date.
        </HelperTextItem>
      </HelperText>
    </FormGroup>
  </div>
);

export default LanguageStep;
