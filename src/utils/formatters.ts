/**
 * Converts Persian and Arabic digits to standard Latin (ASCII) digits.
 */
export const toEnglishDigits = (input: string | number | null | undefined): string => {
  if (input === null || input === undefined) return '';
  return String(input)
    .replace(/[۰-۹]/g, (char) => String(char.charCodeAt(0) - 1776))
    .replace(/[٠-٩]/g, (char) => String(char.charCodeAt(0) - 1632));
};

/**
 * Converts Latin digits to Persian digits.
 */
export const toPersianDigits = (input: string | number | null | undefined): string => {
  if (input === null || input === undefined) return '';
  const str = String(input);
  if (!str.trim()) return '';
  return str.replace(/\d/g, (char) => String.fromCharCode(char.charCodeAt(0) + 1728));
};
