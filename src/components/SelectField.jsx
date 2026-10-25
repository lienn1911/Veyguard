import Icon from './Icon.jsx';
import React, { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

export default function SelectField({ label, value, options, onChange, disabled = false }) {
  const id = useId();
  const trigger = useRef(null);
  const menu = useRef(null);
  const search = useRef({ value: '', time: 0 });
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [position, setPosition] = useState({});
  const selected = options.findIndex((option) => option.value === value);

  function show(index = Math.max(0, selected)) {
    setActive(index);
    setOpen(true);
  }

  function choose(index) {
    if (!options[index]) return;
    onChange(options[index].value);
    setOpen(false);
    trigger.current?.focus();
  }

  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = trigger.current.getBoundingClientRect();
      const height = Math.min(options.length * 38 + 10, 280);
      const below = window.innerHeight - rect.bottom - 12;
      const above = rect.top - 12;
      const flip = below < height && above > below;
      const maxHeight = Math.max(0, Math.min(280, flip ? above : below));
      const width = Math.min(rect.width, window.innerWidth - 16);
      setPosition({
        left: Math.max(8, Math.min(rect.left, window.innerWidth - width - 8)),
        width,
        top: flip ? undefined : rect.bottom + 6,
        bottom: flip ? window.innerHeight - rect.top + 6 : undefined,
        maxHeight,
      });
    };
    place();
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
  }, [open, options.length]);

  useEffect(() => {
    if (!open) return;
    const outside = (event) => {
      if (!trigger.current?.contains(event.target) && !menu.current?.contains(event.target))
        setOpen(false);
    };
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [open]);

  useEffect(() => {
    if (open)
      menu.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [open, active]);

  function onKeyDown(event) {
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      const next =
        event.key === 'Home'
          ? 0
          : event.key === 'End'
            ? options.length - 1
            : !open
              ? Math.max(0, selected)
              : (active + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length;
      show(next);
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      if (open) choose(active);
      else show();
    } else if (event.key === 'Escape' || event.key === 'Tab') {
      if (event.key === 'Escape' && open) event.preventDefault();
      setOpen(false);
    } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const now = Date.now();
      search.current = {
        value: now - search.current.time > 600 ? event.key : search.current.value + event.key,
        time: now,
      };
      const index = options.findIndex((option) =>
        option.label.toLowerCase().startsWith(search.current.value.toLowerCase()),
      );
      if (index >= 0) {
        event.preventDefault();
        show(index);
      }
    }
  }

  return (
    <div className="select-field">
      <label id={`${id}-label`} htmlFor={`${id}-trigger`}>
        {label}
      </label>
      <button
        ref={trigger}
        id={`${id}-trigger`}
        type="button"
        className="select-field-trigger"
        role="combobox"
        aria-labelledby={`${id}-label ${id}-value`}
        aria-expanded={open}
        aria-controls={open ? `${id}-list` : undefined}
        aria-haspopup="listbox"
        aria-activedescendant={open ? `${id}-option-${active}` : undefined}
        disabled={disabled}
        onKeyDown={onKeyDown}
        onBlur={(event) => {
          if (!menu.current?.contains(event.relatedTarget)) setOpen(false);
        }}
        onClick={() => (open ? setOpen(false) : show())}
      >
        <span id={`${id}-value`}>{options[selected]?.label || 'Choose an option'}</span>
        <Icon name="chevronDown" size={16} className="select-field-chevron" />
      </button>
      {open &&
        createPortal(
          <div
            ref={menu}
            id={`${id}-list`}
            className="select-field-menu"
            role="listbox"
            aria-labelledby={`${id}-label`}
            style={position}
            onMouseDown={(event) => event.preventDefault()}
          >
            {options.map((option, index) => (
              <div
                key={option.value}
                id={`${id}-option-${index}`}
                role="option"
                aria-selected={index === selected}
                data-index={index}
                data-active={index === active}
                className="select-field-option"
                onPointerMove={() => setActive(index)}
                onClick={() => choose(index)}
              >
                <span>{option.label}</span>
                {index === selected && <Icon name="check" size={16} />}
              </div>
            ))}
          </div>,
          document.body,
        )}
    </div>
  );
}
