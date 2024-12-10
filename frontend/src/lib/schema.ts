export interface IssueSchema {
    id: string | undefined,
    title: string;
    description: string;
    status: "todo" | "inprogress" | "done" | "backlog";
    label: "bug" | "feature" | "documentation";
    author: string;
}

export interface UserSchema {
    id: string,
    first_name: string,
    last_name: string,
    username: string,
    profile_image_url: string,
}

import { create } from 'zustand'

type IssueStore = {
    edit_issue_id: string,
    setEditIssueId: (id: string) => void
}
export const useIssueStore = create<IssueStore>((set) => ({
    edit_issue_id: "",
    setEditIssueId: (id: string) => set(() => ({ edit_issue_id: id })),
}))

type IssueModalStore = {
    isOpen: boolean,
    setOpen: () => void
    setClose: () => void
}
export const useIssueModalStore = create<IssueModalStore>((set) => ({
    isOpen: false,
    setOpen: () => set({ isOpen: true }),
    setClose: () => set({ isOpen: false }),
}))

