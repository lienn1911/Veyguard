import React, { useEffect, useRef } from 'react';
import { useReducedMotion } from 'motion/react';
import { TrendingUpIcon } from './animated-icons/trending-up';
import { TrendingDownIcon } from './animated-icons/trending-down';
import { FileCogIcon } from './animated-icons/file-cog';
import { ArrowLeftIcon } from './animated-icons/arrow-left';
import { ArrowRightIcon } from './animated-icons/arrow-right';
import { BadgeAlertIcon } from './animated-icons/badge-alert';
import { BrainIcon } from './animated-icons/brain';
import { CheckIcon } from './animated-icons/check';
import { CheckCheckIcon } from './animated-icons/check-check';
import { ChevronDownIcon } from './animated-icons/chevron-down';
import { ChevronLeftIcon } from './animated-icons/chevron-left';
import { CircleCheckIcon } from './animated-icons/circle-check';
import { CircleHelpIcon } from './animated-icons/circle-help';
import { ClipboardCheckIcon } from './animated-icons/clipboard-check';
import { DatabaseBackupIcon } from './animated-icons/database-backup';
import { DownloadIcon } from './animated-icons/download';
import { EyeIcon } from './animated-icons/eye';
import { EyeOffIcon } from './animated-icons/eye-off';
import { FileCheckIcon } from './animated-icons/file-check';
import { FileTextIcon } from './animated-icons/file-text';
import { FolderOpenIcon } from './animated-icons/folder-open';
import { HistoryIcon } from './animated-icons/history';
import { HomeIcon } from './animated-icons/home';
import { LogInIcon } from './animated-icons/login';
import { PanelLeftCloseIcon } from './animated-icons/panel-left-close';
import { PanelLeftOpenIcon } from './animated-icons/panel-left-open';
import { PlugZapIcon } from './animated-icons/plug-zap';
import { RefreshCWIcon } from './animated-icons/refresh-cw';
import { RouteIcon } from './animated-icons/route';
import { SearchIcon } from './animated-icons/search';
import { SettingsIcon } from './animated-icons/settings';
import { ShieldCheckIcon } from './animated-icons/shield-check';
import { UserIcon } from './animated-icons/user';
import { WorkflowIcon } from './animated-icons/workflow';
import { XIcon } from './animated-icons/x';

export const iconRegistry = {
  priorityHigh: TrendingUpIcon,
  priorityLow: TrendingDownIcon,
  saveSettings: FileCogIcon,
  arrow: ArrowRightIcon,
  back: ChevronLeftIcon,
  previous: ArrowLeftIcon,
  check: CheckIcon,
  copied: CheckCheckIcon,
  home: HomeIcon,
  network: WorkflowIcon,
  audit: HistoryIcon,
  database: DatabaseBackupIcon,
  refresh: RefreshCWIcon,
  connection: PlugZapIcon,
  save: FileCheckIcon,
  file: FileTextIcon,
  download: DownloadIcon,
  analysis: BrainIcon,
  checklist: ClipboardCheckIcon,
  checkCircle: CircleCheckIcon,
  search: SearchIcon,
  shield: ShieldCheckIcon,
  alert: BadgeAlertIcon,
  flow: RouteIcon,
  close: XIcon,
  user: UserIcon,
  show: EyeIcon,
  hide: EyeOffIcon,
  collapse: PanelLeftCloseIcon,
  expand: PanelLeftOpenIcon,
  chevronDown: ChevronDownIcon,
  info: CircleHelpIcon,
  settings: SettingsIcon,
  login: LogInIcon,
  viewRecord: FolderOpenIcon,
};

export default function Icon({ name, size = 20, className = '' }) {
  const wrapper = useRef(null);
  const animation = useRef(null);
  const reduceMotion = useReducedMotion();
  const Component = iconRegistry[name];

  useEffect(() => {
    const node = wrapper.current;
    if (!node || reduceMotion || !Component) return;
    const target = node.closest('button, a, summary, [role="button"], [role="combobox"]') || node;
    const start = () => {
      if (!target.disabled && target.getAttribute('aria-disabled') !== 'true') {
        animation.current?.startAnimation();
      }
    };
    const stop = () => animation.current?.stopAnimation();
    const listeners = [
      ['pointerenter', start],
      ['pointerleave', stop],
      ['focusin', start],
      ['focusout', stop],
      ['click', start],
    ];
    listeners.forEach(([event, handler]) => target.addEventListener(event, handler));
    return () =>
      listeners.forEach(([event, handler]) => target.removeEventListener(event, handler));
  }, [name, reduceMotion, Component]);

  if (!Component) return null;
  return (
    <span
      ref={wrapper}
      className={`app-icon ${className}`.trim()}
      data-icon={name}
      aria-hidden="true"
      style={{ width: size, height: size }}
    >
      <Component ref={animation} size={size} className="animated-icon-glyph" />
    </span>
  );
}
