import { TableCell, TableRow } from "@/components/ui/table";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import {
  Bug,
  CheckCircle,
  Circle,
  Edit,
  Eye,
  File,
  HelpCircle,
  Loader,
  Rocket,
  Timer,
  Trash2,
} from "lucide-react";
import { useDeleteIssue, useGetUser } from "@/lib/hooks";
import { IssueSchema } from "@/lib/schema";
import { useIssueModalStore, useIssueStore } from "@/lib/schema";
import { Button } from "../ui/button";
import { useUser } from "@clerk/clerk-react";

const statusIcon = {
  todo: <Circle className="mr-2 h-4 w-4 text-muted-foreground" />,
  inprogress: <Timer className="mr-2 h-4 w-4 text-muted-foreground" />,
  done: <CheckCircle className="mr-2 h-4 w-4 text-muted-foreground" />,
  backlog: <HelpCircle className="mr-2 h-4 w-4 text-muted-foreground" />,
};

const labelIcon = {
  bug: <Bug className="mr-2 h-4 w-4 text-muted-foreground" />,
  feature: <Rocket className="mr-2 h-4 w-4 text-muted-foreground" />,
  documentation: <File className="mr-2 h-4 w-4 text-muted-foreground" />,
};

const Row = ({ task }: { task: IssueSchema }) => {
  const userData = useGetUser(task.author);
  const { setEditIssueId } = useIssueStore();
  const { setOpen } = useIssueModalStore();
  const { isMutating, trigger } = useDeleteIssue();
  const { user } = useUser();

  return (
    <TableRow>
      <TableCell width={"200px"}>
        {userData.isLoading ? (
          <Loader className="w-3 h-3 animate-spin" />
        ) : (
          <div className="flex items-center gap-3">
            <Avatar>
              <AvatarImage src={userData.data?.profile_image_url} />
              <AvatarFallback>{userData.data?.username}</AvatarFallback>
            </Avatar>
            <p className="font-medium">{userData.data?.username}</p>
          </div>
        )}
      </TableCell>
      <TableCell>{task.title}</TableCell>
      <TableCell width={"300px"}>{task.description}</TableCell>
      <TableCell width={"150px"}>
        <div className="flex items-center">
          {statusIcon[task.status]}
          <span>{task.status.toUpperCase()}</span>
        </div>
      </TableCell>
      <TableCell width={"150px"}>
        <div className="flex items-center">
          {labelIcon[task.label]}
          <span>{task.label.toUpperCase()}</span>
        </div>
      </TableCell>
      <TableCell width={"100px"}>
        <div className="flex items-center gap-4">
          <Button
            variant={"ghost"}
            onClick={() => task.id && (setEditIssueId(task.id), setOpen())}
          >
            {user?.id === task.author ? (
              <Edit className="w-4 h-4" />
            ) : (
              <Eye className="w-4 h-4" />
            )}
          </Button>

          {user?.id === task.author && (
            <Button
              variant={"ghost"}
              onClick={() => task.id && trigger({ id: task.id })}
            >
              {isMutating ? (
                <Loader className="w-4 h-4 animate-spin" />
              ) : (
                <Trash2 className="w-4 h-4" />
              )}
            </Button>
          )}
        </div>
      </TableCell>
    </TableRow>
  );
};

export default Row;