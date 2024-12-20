import useSWR, { Fetcher, useSWRConfig } from "swr"
import useSWRMutation from 'swr/mutation'
import { IssueSchema, UserSchema } from "./schema";
import { toast } from "sonner";
import { useIssueModalStore } from "./schema";

export const useGetUser = (user_id: string | undefined) => {
    const fetcher: Fetcher<UserSchema, string> = (url) => fetch(url).then(res => res.json())
    const { isLoading, data } = useSWR(`/api/user/${user_id}`, fetcher);
    return { isLoading, data };
}

export const useGetIssues = () => {
    const fetcher: Fetcher<IssueSchema[], string> = (url) =>
        fetch(url).then((res) => res.json())
    const { isLoading, data } = useSWR('/api/issues', (url) => fetcher(url));
    return { isLoading, data };
}

export const useGetIssue = (id: string) => {
    const fetcher: Fetcher<{ data: IssueSchema }, string> = (url) =>
        fetch(url).then((res) => res.json())
    const { data } = useSWR(() => id !== "" ? `/api/issue/${id}` : null, fetcher);

    return { data: data?.data }
}

export const useCreateIssue = () => {
    const { setClose } = useIssueModalStore();

    const create = (url: string, { arg }: { arg: Omit<IssueSchema, "id"> }) => fetch(url, {
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify(arg),
    }).then(res => res.json())

    const { mutate: revalidateIssuesList } = useSWRConfig();

    const { isMutating, trigger } = useSWRMutation("/api/issue", create, {
        onSuccess() {
            toast.success("Issue has been created.");
            setClose();
            revalidateIssuesList("/api/issues")
        },
        onError(err) {
            if (err.message) {
                toast.error(err.message);
            } else {
                toast.error("Failed to create issue");
            }
        },
    })

    return { isMutating, trigger }
}

export const useEditIssue = () => {
    const { setClose } = useIssueModalStore();

    const edit = (url: string, { arg }: { arg: IssueSchema }) => fetch(`${url}/${arg.id}`, {
        method: "PATCH",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify(arg),
    }).then(res => res.json())

    const { mutate: revalidateIssuesList } = useSWRConfig();

    const { isMutating, trigger } = useSWRMutation("/api/issue", edit, {
        onSuccess() {
            toast.success("Issue has been updated.");
            setClose();
            revalidateIssuesList("/api/issues")
        },
        onError(err) {
            if (err.message) {
                toast.error(err.message);
            } else {
                toast.error("Failed to update issue");
            }
        },
    })

    return { isMutating, trigger }
}

export const useDeleteIssue = () => {
    const { setClose } = useIssueModalStore();

    const remove = (url: string, { arg }: { arg: { id: string } }) => fetch(`${url}/${arg.id}`, {
        method: "DELETE",
    }).then(res => res.json())

    const { mutate: revalidateIssuesList } = useSWRConfig();

    const { isMutating, trigger } = useSWRMutation("/api/issue", remove, {
        onSuccess() {
            toast.success("Issue has been deleted.");
            setClose();
            revalidateIssuesList("/api/issues")
        },
        onError(err) {
            if (err.message) {
                toast.error(err.message);
            } else {
                toast.error("Failed to delete issue");
            }
        },
    })

    return { isMutating, trigger }
}