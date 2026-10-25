// Unknown cases still need assessment; never silently put them behind Low.
export const priorityRank = (priority) => ({ High: 3, Medium: 2, Low: 1 })[priority?.level] ?? 3;
